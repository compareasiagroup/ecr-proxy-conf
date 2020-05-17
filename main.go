package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/Masterminds/sprig"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecr/ecriface"
	"gopkg.in/matryer/try.v1"
)

type (
	// Config struct map with for parameters
	Config struct {
		// HealthPort is used for health checks
		HealthPort int
		// ProxyPort configures what port the proxy will listen on
		ProxyPort int
		// TargetPath to render proxy config to
		TargetPath string
		// TemplateDir to scan for TemplateFile
		TemplateDir string
		// TemplateFile used to render proxy config
		TemplateFile string
		// Ssl flag to handle HTTPS
		Ssl bool
		// SslKey path for Ssl private key
		SslKey string
		// SslCert path for Ssl public cert
		SslCert string
		// Resolver used by proxy
		Resolver string
		// LogLevel controls command verbosity
		LogLevel string
		// Interval to update proxy config
		Interval string
		// MaxRetries for ecr auth
		MaxRetries int
		// CacheKey used for the content by proxy
		CacheKey string
		// CacheMaxSize Maximum size for cache volume
		CacheMaxSize string
		// CachePath volume to store cache
		CachePath string
	}

	// Command struct
	Command struct {
		// Configuration of the command
		Config *Config
		// ConfigTemplate string
	}

	ecrAuth struct {
		username string
		password string
		host     string
	}

	// private struct used to render
	data struct {
		Upstream  string
		BasicAuth string
		Config    Config
	}

	sslConfig struct {
		Enabled bool
		Key     string
		Cert    string
	}
)

// updateEcrAuth with maxRetries
func (c Command) updateEcrAuth(svc ecriface.ECRAPI) (*ecrAuth, error) { //, registryIds []string) {
	log.Info("Updating ECR Credentials")

	request := &ecr.GetAuthorizationTokenInput{}
	// if len(registryIds) > 0 {
	// 	request = &ecr.GetAuthorizationTokenInput{RegistryIds: aws.StringSlice(registryIds)}
	// }
	auth := &ecrAuth{}
	err := try.Do(func(attempt int) (bool, error) {
		var err error
		var maxRetries = c.Config.MaxRetries
		// exponential back off
		var retryDuration = time.Duration(attempt) * time.Second * 100

		log.Info("Attempting to call AWS API for ECR Authorization Token")
		resp, err := svc.GetAuthorizationToken(request)
		log.Debug(resp)
		if err != nil {
			log.Errorf("Error calling AWS API: %s\n", err)
			log.Infof("Sleeping before retry for %s ", retryDuration)
			time.Sleep(retryDuration)
			return attempt < maxRetries, err
		}
		log.Println("Returned from AWS GetAuthorizationToken call successfully")

		if len(resp.AuthorizationData) < 1 {
			log.Errorln("Request did not return authorization data")
			log.Infof("Sleeping before retry for %s ", retryDuration)
			time.Sleep(retryDuration)
			return attempt < maxRetries, err
		}

		for _, data := range resp.AuthorizationData {
			err = processToken(data, auth)
		}
		if err != nil && attempt < maxRetries {
			log.Infof("Sleeping before retry for %s ", retryDuration)
			time.Sleep(retryDuration)
		}
		return attempt < maxRetries, err
	})
	if err != nil {
		return nil, fmt.Errorf("max retries for AWS API reached. Last error: %s", err)
	}
	return auth, nil
}

// renderProxyConf to specified file
func (c Command) renderProxyConf(auth *ecrAuth, f *os.File) error {
	nginxConf := filepath.Join(c.Config.TemplateDir, c.Config.TemplateFile)
	log.Infof("Parsing and executing %v", nginxConf)
	tmpl, err := template.New("").Funcs(sprig.TxtFuncMap()).ParseFiles(nginxConf)
	if err != nil {
		return fmt.Errorf("Parse %q failed: %v", nginxConf, err)
	}

	log.Debugf("Rendering proxy config for (%s, %s, %s)", auth.username, auth.password, auth.host)
	authstr := auth.username + ":" + auth.password
	d := data{
		Upstream:  auth.host,
		BasicAuth: base64.StdEncoding.EncodeToString([]byte(authstr)),
		Config:    *c.Config,
	}
	if err := tmpl.ExecuteTemplate(f, c.Config.TemplateFile, d); err != nil {
		return fmt.Errorf("Execute template failed: %v", err)
	}
	return nil
}

// reloadProxyWithTest by overwriting config if test is successful
func (c Command) reloadProxyWithTest(tempFile *os.File) error {
	if err := execCommand("/", []string{"nginx", "-t", "-c", tempFile.Name()}); err != nil {
		return fmt.Errorf("Aborting reload: error validating %q: %v", tempFile.Name(), err)
	}
	if _, err := moveFile(c.Config.TargetPath, tempFile.Name()); err != nil {
		return fmt.Errorf("Aborting reload: renaming %q to %q failed: %v", tempFile.Name(), c.Config.TargetPath, err)
	}
	if err := execCommand("/", []string{"nginx", "-s", "reload", "-c", tempFile.Name()}); err != nil {
		return fmt.Errorf("Aborting reload: error signaling nginx process: %v", err)
	}
	return nil
}

func (c Command) loop() error {
	// if ids, ok := os.LookupEnv("AWS_ECR_REGISTRY_IDS"); ok && ids != "" {
	// 	log.Debug("Detected AWS_ECR_REGISTRY_IDS config param")
	// 	registryIds = strings.Split(ids, ",")
	// }

	// parse the duration
	dur, err := time.ParseDuration(c.Config.Interval)
	if err != nil {
		return fmt.Errorf("Parsing %s as duration failed: %v", c.Config.Interval, err)
	}

	// start hc thread
	go healthcheck(c.Config.HealthPort)

	// render and reload on interval
	ticker := time.NewTicker(dur)
	log.Infof("sleeping for %v ...", c.Config.Interval)
	for range ticker.C {
		if auth, err := c.updateEcrAuth(awsClient()); err != nil {
			log.Error(err)
		} else {
			log.Info("Creating temporary file for template")
			f, err := ioutil.TempFile("", "ecr-proxy-conf")
			if err != nil {
				return fmt.Errorf("creating temp file failed: %v", err)
			}
			defer f.Close()
			defer os.Remove(f.Name())
			if err := c.renderProxyConf(auth, f); err != nil {
				log.Error(err)
			} else if err := c.reloadProxyWithTest(f); err != nil {
				log.Error(err)
			}
		}
	}
	return nil
}

func (c Command) init() (err error) {
	// do initial render
	var auth *ecrAuth
	if auth, err = c.updateEcrAuth(awsClient()); err != nil {
		return err
	}
	f, err := os.Create(c.Config.TargetPath)
	if err != nil {
		return fmt.Errorf("creating config file failed: %v", err)
	}
	defer f.Close()
	if err := c.renderProxyConf(auth, f); err != nil {
		return err
	}
	if err := execCommand("/", []string{"nginx", "-t", "-c", f.Name()}); err != nil {
		return fmt.Errorf("Error in init: error validating %q: %v", f.Name(), err)
	}
	return nil
}

func initApp() *cli.App {
	conf := &Config{}
	app := &cli.App{
		Name:    "ecr-proxy-conf",
		Usage:   "Configuration generator for nginx proxy to ECR",
		Version: fmt.Sprintf("0.1.0"),
		Commands: []*cli.Command{
			{
				Name:  "init",
				Usage: "Initialise proxy config",
				Action: func(c *cli.Context) error {
					if err := setLogger(conf); err != nil {
						return err
					}
					cmd := Command{
						Config: conf,
					}
					return cmd.init()
				},
			},
			{
				Name:  "loop",
				Usage: "Infinitely loop to refresh ECR Credentials on an interval",
				Action: func(c *cli.Context) error {
					if err := setLogger(conf); err != nil {
						return err
					}
					cmd := Command{
						Config: conf,
					}
					return cmd.loop()
				},
			},
		},
	}

	mainFlags := []cli.Flag{
		&cli.IntFlag{
			Name:        "health-port",
			Aliases:     []string{"p"},
			Value:       8080,
			Usage:       "Port to expose healthchecks on",
			Destination: &conf.HealthPort,
			EnvVars:     []string{"CONF_HEALTH_PORT"},
		},
		&cli.IntFlag{
			Name:        "proxy-port",
			Value:       80,
			Usage:       "Port to configure proxy to listen on",
			Destination: &conf.ProxyPort,
			EnvVars:     []string{"CONF_PROXY_PORT"},
		},
		&cli.StringFlag{
			Name:        "proxy-resolver",
			Aliases:     []string{"r"},
			Value:       "8.8.8.8",
			Usage:       "Resolver config for proxy",
			Destination: &conf.Resolver,
			EnvVars:     []string{"CONF_PROXY_RESOLVER"},
		},
		&cli.StringFlag{
			Name:        "proxy-cache-key",
			Value:       "$uri",
			Usage:       "Cache key used for the content by proxy",
			Destination: &conf.CacheKey,
			EnvVars:     []string{"CONF_PROXY_CACHE_KEY"},
		},
		&cli.StringFlag{
			Name:        "proxy-cache-max-size",
			Value:       "75g",
			Usage:       "Maximum size for cache volume",
			Destination: &conf.CacheMaxSize,
			EnvVars:     []string{"CONF_PROXY_CACHE_MAX_SIZE"},
		},
		&cli.StringFlag{
			Name:        "proxy-cache-path",
			Value:       "/cache/cache",
			Usage:       "Path to for proxy to store cache",
			Destination: &conf.CachePath,
			EnvVars:     []string{"CONF_PROXY_CACHE_PATH"},
		},
		&cli.StringFlag{
			Name:        "target-path",
			Aliases:     []string{"t"},
			Value:       "/etc/nginx/nginx.conf",
			Usage:       "Destination path for rendered proxy config",
			Destination: &conf.TargetPath,
			EnvVars:     []string{"CONF_TARGET_PATH"},
		},
		&cli.StringFlag{
			Name:        "template-dir",
			Value:       "conf-templates",
			Usage:       "Path to directory of config templates",
			Destination: &conf.TemplateDir,
			EnvVars:     []string{"CONF_TEMPLATE_DIR"},
		},
		&cli.StringFlag{
			Name:        "template-file",
			Value:       "nginx.tpl.conf",
			Usage:       "template file to render",
			Destination: &conf.TemplateFile,
			EnvVars:     []string{"CONF_TEMPLATE_FILE"},
		},
		&cli.BoolFlag{
			Name:        "ssl",
			Aliases:     []string{"s"},
			Value:       false,
			Usage:       "Flag to enable ssl",
			Destination: &conf.Ssl,
		},
		&cli.StringFlag{
			Name:        "ssl-key",
			Value:       "/etc/nginx/ssl/key.pem",
			Usage:       "Path to private key, required if SSL is enabled",
			Destination: &conf.SslKey,
			EnvVars:     []string{"CONF_SSL_KEY_PATH"},
		},
		&cli.StringFlag{
			Name:        "ssl-cert",
			Value:       "/etc/nginx/ssl/certificate.pem",
			Usage:       "Path to public cert of private key, required if SSL is enabled",
			Destination: &conf.SslCert,
			EnvVars:     []string{"CONF_SSL_CERT_PATH"},
		},
		&cli.StringFlag{
			Name:        "interval",
			Value:       "6h",
			Usage:       "Interval to fetch new ECR credentials at",
			Destination: &conf.Interval,
			EnvVars:     []string{"CONF_INTERVAL"},
		},
		&cli.IntFlag{
			Name:        "max-retries",
			Value:       10,
			Usage:       "Maximum times to retry ECR Auth with exponential back-off",
			Destination: &conf.MaxRetries,
			EnvVars:     []string{"CONF_MAX_RETRIES"},
		},
		&cli.StringFlag{
			Name:        "log-level",
			Aliases:     []string{"l"},
			Value:       "error",
			Usage:       "Log level (panic, fatal, error, warn, info, or debug)",
			Destination: &conf.LogLevel,
			EnvVars:     []string{"LOG_LEVEL"},
		},
	}
	app.Flags = mainFlags

	return app
}

func main() {
	app := initApp()
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

// HELPER FUNCTIONS ----------------

// parse ecr.AuthorizationData into ecrAuth object passed by reference
func processToken(data *ecr.AuthorizationData, ecrConf *ecrAuth) error {
	bytes, err := base64.StdEncoding.DecodeString(*data.AuthorizationToken)
	if err != nil {
		log.Debugf("[%s] Error decoding authorization token: %s\n", *data.ProxyEndpoint, err)
		return err
	}
	token := string(bytes[:len(bytes)])

	authTokens := strings.Split(token, ":")
	if len(authTokens) != 2 {
		log.Debugf("[%s] Authorization token does not contain data in <user>:<password> format: %s\n", *data.ProxyEndpoint, token)
		return errors.New("authorization token in incorrect format")
	}

	registryURL, err := url.Parse(*data.ProxyEndpoint)
	if err != nil {
		log.Debugf("[%s] Error parsing registry URL: %s\n", *data.ProxyEndpoint, err)
		return err
	}

	ecrConf.username = authTokens[0]
	ecrConf.password = authTokens[1]
	ecrConf.host = registryURL.Host
	return nil
}

func moveFile(dst, src string) (int64, error) {
	sf, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer sf.Close()

	df, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer df.Close()

	i, err := io.Copy(df, sf)
	if err != nil {
		return i, err
	}

	// Cleanup
	err = os.Remove(src)
	return i, err
}

func healthcheck(listenport int) {
	http.HandleFunc("/ping", ping)
	log.Printf("Starting Healthcheck listener at :%d/ping\n", listenport)
	err := http.ListenAndServe(fmt.Sprintf(":%d", listenport), nil)
	if err != nil {
		log.Fatal("Error creating health check listener: ", err)
	}
}

func ping(w http.ResponseWriter, r *http.Request) {
	log.Debug("Recieved Health Check Request")
	fmt.Fprintf(w, "pong!")
}

func awsClient() *ecr.ECR {
	roleArn, ok := os.LookupEnv("AWS_ROLE_ARN")
	if ok {
		log.Printf("[awsClient] Assuming Role: %s\n", roleArn)
		return ecr.New(
			session.New(
				aws.NewConfig().WithCredentials(
					stscreds.NewCredentials(session.New(), roleArn),
				),
			),
		)
	}
	return ecr.New(session.New())
}

func execCommand(tempPath string, commandArray []string) error {
	log.Debugf("executing %q in %q", commandArray, tempPath)
	targetCmd := exec.Command(commandArray[0], commandArray[1:]...)
	targetCmd.Dir = tempPath
	targetCmd.Stdout = os.Stdout
	targetCmd.Stderr = os.Stderr
	if err := targetCmd.Start(); err != nil {
		return err
	}
	return targetCmd.Wait()
}

func setLogger(conf *Config) error {
	logLevel, err := log.ParseLevel(conf.LogLevel)
	if err != nil {
		return err
	}
	log.SetLevel(logLevel)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	return nil
}
