package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
)

type User struct {
	Account              string                 `yaml:"account,omitempty"`
	Name                 string                 `yaml:"name,omitempty"`
	AllowPub             Permissions            `yaml:"allow_pub,omitempty"`
	AllowSub             Permissions            `yaml:"allow_sub,omitempty"`
	AllowSubOverConsumer []AllowSubOverConsumer `yaml:"allow_sub_over_consumer,omitempty"`
}

type Permissions = []string

type AllowSubOverConsumer struct {
	Name   string `yaml:"name,omitempty"`
	Stream string `yaml:"stream,omitempty"`
}

const (
	App                         = "NSC_USER_CREATOR"
	CliConfigFile               = "config_file"
	CliCredsFileTarget          = "creds_file_target"
	CliAccountSeed              = "account_seed"
	CliLowerSecInboxPermissions = "lower_inbox_permissions"
)

func getFlagEnvByFlagName(flagName string) string {
	return fmt.Sprintf("%s_%s", App, strings.ToUpper(flagName))
}

func main() {
	runner := Runner{}
	app := &cli.App{
		Usage:  "nsc_user_creator",
		Action: runner.Run,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    CliConfigFile,
				EnvVars: []string{getFlagEnvByFlagName(CliConfigFile)},
				Usage:   "Configfile where user permission is set",
				Value:   "nsc_user.yml",
			},
			&cli.StringFlag{
				Name:    CliCredsFileTarget,
				EnvVars: []string{getFlagEnvByFlagName(CliCredsFileTarget)},
				Usage:   "Target to save credsfile",
				Value:   "nats-user.creds",
			},
			&cli.StringFlag{
				Name:     CliAccountSeed,
				EnvVars:  []string{getFlagEnvByFlagName(CliAccountSeed)},
				Usage:    "Seed from account where to add user",
				Required: true,
			},
			&cli.BoolFlag{
				Name:    CliLowerSecInboxPermissions,
				EnvVars: []string{getFlagEnvByFlagName(CliLowerSecInboxPermissions)},
				Usage:   "if true Add Sub Permissions _INBOX.* and _INBOX.*.* if min one consumer is described at configfile",
				Value:   true,
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Panic("Application start failed", "error", err)
	}
}

type Runner struct{}

func (r *Runner) Run(c *cli.Context) error {
	accountSeed := c.String(CliAccountSeed)
	configFilePath := c.String(CliConfigFile)
	useLowerSecInboxPermissions := c.Bool(CliLowerSecInboxPermissions)
	targetFile := c.String(CliCredsFileTarget)
	u, err := r.getConf(configFilePath)
	if err != nil {
		return err
	}
	accountKP, err := nkeys.ParseDecoratedNKey([]byte(accountSeed))
	if err != nil {
		return err
	}

	user, err := nkeys.CreateUser()
	if err != nil {
		return err
	}

	userPub, err := user.PublicKey()
	if err != nil {
		return err
	}
	userSeed, err := user.Seed()
	if err != nil {
		return err
	}
	userClaims := jwt.NewUserClaims(userPub)
	userClaims.Name = u.Name
	userClaims.Permissions.Pub.Allow.Add(u.AllowPub...)
	userClaims.Permissions.Sub.Allow.Add(u.AllowSub...)
	for _, consumer := range u.AllowSubOverConsumer {
		userClaims.Permissions.Pub.Allow.Add(
			fmt.Sprintf("$JS.ACK.%s.%s.>", consumer.Stream, consumer.Name),
			fmt.Sprintf("$JS.API.CONSUMER.MSG.NEXT.%s.%s", consumer.Stream, consumer.Name),
			fmt.Sprintf("$JS.API.CONSUMER.INFO.%s.%s", consumer.Stream, consumer.Name),
		)
	}
	if len(u.AllowSubOverConsumer) > 0 && useLowerSecInboxPermissions {
		userClaims.Permissions.Sub.Allow.Add("_INBOX.*", "_INBOX.*.*")
	}
	userJWT, err := userClaims.Encode(accountKP)
	if err != nil {
		return err
	}
	creds, err := jwt.FormatUserConfig(userJWT, userSeed)
	if err != nil {
		return err
	}
	err = os.WriteFile(targetFile, creds, 0600)
	if err != nil {
		return err
	}
	return nil

}

func (r *Runner) getConf(configFilePath string) (User, error) {

	yamlFile, err := os.ReadFile(configFilePath)
	if err != nil {
		return User{}, err
	}

	var result User

	err = yaml.Unmarshal(yamlFile, &result)
	return result, err
}
