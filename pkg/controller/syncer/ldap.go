package syncer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	ldap "github.com/go-ldap/ldap/v3"
	userv1 "github.com/openshift/api/user/v1"
	redhatcopv1alpha1 "github.com/redhat-cop/group-sync-operator/pkg/apis/redhatcop/v1alpha1"
	"github.com/redhat-cop/operator-utils/pkg/util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	ldapLogger = logf.Log.WithName("syncer_ldap")
)

type LdapSyncer struct {
	Name              string
	GroupSync         *redhatcopv1alpha1.GroupSync
	Provider          *redhatcopv1alpha1.LDAPProvider
	CredentialsSecret *corev1.Secret
	CaCertificate     []byte
	ReconcilerBase    util.ReconcilerBase
	LdapConn          *ldap.Conn
}

//Init creates an LDAP Syncer
//func (l *LdapSyncer) Init() bool {
//	changed := false
//}

//Validate ensures that things are the way they should be
func (l *LdapSyncer) Validate() error {
	validationErrors := []error{}

	//Verify secret containing username and password exists with valid keys
	credentialsSecret := &corev1.Secret{}
	err := l.ReconcilerBase.GetClient().Get(context.TODO(), types.NamespacedName{Name: l.Provider.CredentialsSecret.Name,
		Namespace: l.Provider.CredentialsSecret.Namespace}, credentialsSecret)

	if err != nil {
		validationErrors = append(validationErrors, err)
	} else {
		// Username validation
		if _, found := credentialsSecret.Data[secretUsernameKey]; !found {
			validationErrors = append(validationErrors, fmt.Errorf("Could not find 'username' key in secret '%s' in namespace '%s'",
				l.Provider.CredentialsSecret.Name, l.Provider.CredentialsSecret.Namespace))
		}

		if _, found := credentialsSecret.Data[secretPasswordKey]; !found {
			validationErrors = append(validationErrors, fmt.Errorf("Could not find 'password' key in secret '%s' in namespace '%s'",
				l.Provider.CredentialsSecret.Name, l.Provider.CredentialsSecret.Namespace))
		}

		l.CredentialsSecret = credentialsSecret
	}

	return utilerrors.NewAggregate(validationErrors)
}

func (l *LdapSyncer) Bind() error {

	tlsConfig := &tls.Config{}
	ldapURL := l.Provider.Protocol + "://" + l.Provider.Host + ":" + l.Provider.Port

	if len(l.CaCertificate) > 0 {
		if tlsConfig.RootCAs == nil {
			tlsConfig.RootCAs = x509.NewCertPool()
		}

		tlsConfig.RootCAs.AppendCertsFromPEM(l.CaCertificate)
	}

	if l.Provider.Insecure == true {
		tlsConfig.InsecureSkipVerify = true
	}

	conn, err := ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		ldapLogger.Error(err, "Unable to establish connection with LDAP Provider")
	}

	err = conn.Bind(string(l.CredentialsSecret.Data[secretUsernameKey]), string(l.CredentialsSecret.Data[secretPasswordKey]))
	if err != nil {
		ldapLogger.Error(err, "Unable to bind against LDAP Provider.")
	}

	l.LdapConn = conn

	ldapLogger.Info("Successfully Authenticated With LDAP Provider.")

	return nil
}

func (l *LdapSyncer) Sync() ([]userv1.Group, error) {

	for _, group := range l.Provider.Groups {
		filter := fmt.Sprintf("(CN=%s)", ldap.EscapeFilter(group))
		search, err := l.LdapConn.Search(ldap.NewSearchRequest(
			l.Provider.GroupSearchBase,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			filter,
			[]string{"dn"},
			nil,
		))

		if err != nil {
			ldapLogger.Info("Unable to retrieve group")
		}
	}
}

func (l *LdapSyncer) GetProviderName() string {
	return l.Name
}
