package helpers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v2"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	policyv1 "k8s.io/api/policy/v1"

	opsterv1 "github.com/Opster/opensearch-k8s-operator/opensearch-operator/api/v1"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/reconcilers/k8s"
	version "github.com/hashicorp/go-version"
	"github.com/samber/lo"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	stsUpdateWaitTime = 30
	updateStepTime    = 3

	stsRevisionLabel = "controller-revision-hash"
)

type InternalUserYaml struct {
	Hash         string   `yaml:"hash"`
	Reserved     bool     `yaml:"reserved"`
	BackendRoles []string `yaml:"backend_roles"`
	Description  string   `yaml:"description"`
}

func ContainsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func GetField(v *appsv1.StatefulSetSpec, field string) interface{} {
	r := reflect.ValueOf(v)
	f := reflect.Indirect(r).FieldByName(field).Interface()
	return f
}

func RemoveIt(ss opsterv1.ComponentStatus, ssSlice []opsterv1.ComponentStatus) []opsterv1.ComponentStatus {
	for idx, v := range ssSlice {
		if ComponentStatusEqual(v, ss) {
			return append(ssSlice[0:idx], ssSlice[idx+1:]...)
		}
	}
	return ssSlice
}

func Replace(remove opsterv1.ComponentStatus, add opsterv1.ComponentStatus, ssSlice []opsterv1.ComponentStatus) []opsterv1.ComponentStatus {
	removedSlice := RemoveIt(remove, ssSlice)
	fullSliced := append(removedSlice, add)
	return fullSliced
}

func ComponentStatusEqual(left opsterv1.ComponentStatus, right opsterv1.ComponentStatus) bool {
	return left.Component == right.Component && left.Description == right.Description && left.Status == right.Status
}

func FindFirstPartial(
	arr []opsterv1.ComponentStatus,
	item opsterv1.ComponentStatus,
	predicator func(opsterv1.ComponentStatus, opsterv1.ComponentStatus) (opsterv1.ComponentStatus, bool),
) (opsterv1.ComponentStatus, bool) {
	for i := 0; i < len(arr); i++ {
		itemInArr, found := predicator(arr[i], item)
		if found {
			return itemInArr, found
		}
	}
	return item, false
}

func FindAllPartial(
	arr []opsterv1.ComponentStatus,
	item opsterv1.ComponentStatus,
	predicator func(opsterv1.ComponentStatus, opsterv1.ComponentStatus) (opsterv1.ComponentStatus, bool),
) []opsterv1.ComponentStatus {
	var result []opsterv1.ComponentStatus

	for i := 0; i < len(arr); i++ {
		itemInArr, found := predicator(arr[i], item)
		if found {
			result = append(result, itemInArr)
		}
	}
	return result
}

func FindByPath(obj interface{}, keys []string) (interface{}, bool) {
	mobj, ok := obj.(map[string]interface{})
	if !ok {
		return nil, false
	}
	for i := 0; i < len(keys)-1; i++ {
		if currentVal, found := mobj[keys[i]]; found {
			subPath, ok := currentVal.(map[string]interface{})
			if !ok {
				return nil, false
			}
			mobj = subPath
		}
	}
	val, ok := mobj[keys[len(keys)-1]]
	return val, ok
}

func CreateRandomSecrets(k8sClient k8s.K8sClient, cr *opsterv1.OpenSearchCluster) error {
	createdAdmin, err := CreateCustomAdminSecrets(k8sClient, cr)
	if err != nil {
		return err
	}
	createdContext, err := CreateCustomAdminContextSecrets(k8sClient, cr)
	if err != nil {
		return err
	}
	if createdAdmin && createdContext {
		return nil
	}
	return err
}

func generateRandomPassword(length int) (string, error) {
	// Define the set of characters you want to use for the password
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var password []byte

	for i := 0; i < length; i++ {
		// Generate a random index for the charset
		randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}

		// Append the random character to the password slice
		password = append(password, charset[randomIndex.Int64()])
	}

	return string(password), nil
}

func PatchRandomSecrets(k8sClient k8s.K8sClient, cr *opsterv1.OpenSearchCluster) (bool, error) {
	randomPasword, _ := generateRandomPassword(15)
	err := updateAdminSecret(k8sClient, cr.Spec.Security.Config.AdminCredentialsSecret.Name, cr.Namespace, randomPasword)
	if err != nil {
		return false, err
	}
	err = updateContextSecret(k8sClient, cr.Spec.Security.Config.SecurityconfigSecret.Name, cr.Namespace, randomPasword)
	if err != nil {
		return false, err
	}
	return true, nil
}

func updateAdminSecret(k8sClient k8s.K8sClient, secretName string, namespace string, randomPassword string) error {
	adminSecret, err := k8sClient.GetSecret(secretName, namespace)
	if err != nil {
		return err
	}
	adminSecret.Data["password"] = []byte(base64.StdEncoding.EncodeToString([]byte(randomPassword)))
	err = k8sClient.UpdateSecret(&adminSecret)
	if err != nil {
		return err
	}
	return nil
}

func updateContextSecret(k8sClient k8s.K8sClient, secretName string, namespace string, randomPassword string) error {
	contextSecret, err := k8sClient.GetSecret(secretName, namespace)
	if err != nil {
		return err
	}
	internalUsers := contextSecret.Data["internal_users.yml"]

	// decodedYaml, err := base64.StdEncoding.DecodeString(string(internalUsers))
	// if err != nil {
	// 	return err
	// }

	var data map[string]InternalUserYaml
	if err := yaml.Unmarshal(internalUsers, &data); err != nil {
		return err
	}

	// // Update the admin password hash
	// _, ok := data["admin"].(map[interface{}]interface{})
	// if !ok {
	// 	return fmt.Errorf("admin key not found in YAML")
	// }

	hash, err := bcrypt.GenerateFromPassword([]byte(randomPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user := data["admin"]
	user.Hash = string(hash)
	data["admin"] = user

	// Marshal the updated data back to YAML
	modifiedYaml, err := yaml.Marshal(data)
	if err != nil {
		return err
	}

	// // Update the secret data with the modified YAML
	contextSecret.Data["internal_users.yml"] = modifiedYaml

	// Update the secret
	err = k8sClient.UpdateSecret(&contextSecret)
	if err != nil {
		return err
	}
	return nil
}

func CreateCustomAdminSecrets(k8sClient k8s.K8sClient, cr *opsterv1.OpenSearchCluster) (bool, error) {
	if cr.Spec.Security != nil && cr.Spec.Security.Config.AdminCredentialsSecret.Name != "" && cr.Spec.Security.RandomAdminSecrets {
		credentialsSecret, err := k8sClient.GetSecret(cr.Spec.Security.Config.AdminCredentialsSecret.Name, cr.Namespace)

		// skip secret creation if already exist
		if err != nil {
			if statusErr, ok := err.(*k8serrors.StatusError); ok {
				statusCode := statusErr.ErrStatus.Code
				if statusCode != 404 {
					return false, err
				}
			}
		} else {
			// check if secret exist
			_, usernameExists := credentialsSecret.Data["username"]
			_, passwordExists := credentialsSecret.Data["password"]

			// skip creation of secrets
			if usernameExists && passwordExists {
				return true, nil
			}
		}

		adminSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cr.Spec.Security.Config.AdminCredentialsSecret.Name,
				Namespace: cr.Namespace,
			},
			StringData: map[string]string{
				"username": "admin",
				"password": "admin",
			},
		}
		_, err = k8sClient.CreateSecret(adminSecret)
		if err != nil {
			return false, err
		}
		return true, nil
	}
	return true, nil
}

func CreateCustomAdminContextSecrets(k8sClient k8s.K8sClient, cr *opsterv1.OpenSearchCluster) (bool, error) {
	if cr.Spec.Security != nil && cr.Spec.Security.Config.SecurityconfigSecret.Name != "" && cr.Spec.Security.RandomAdminSecrets {
		credentialsSecret, err := k8sClient.GetSecret(cr.Spec.Security.Config.SecurityconfigSecret.Name, cr.Namespace)

		// skip secret creation if already exist
		if err != nil {
			if statusErr, ok := err.(*k8serrors.StatusError); ok {
				statusCode := statusErr.ErrStatus.Code
				if statusCode != 404 {
					return false, err
				}
			}
		} else {
			// check if secret exist
			_, internalUsersExists := credentialsSecret.Data["internal_users.yml"]

			// skip creation of secrets
			if internalUsersExists {
				return true, nil
			}
		}

		contextSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cr.Spec.Security.Config.SecurityconfigSecret.Name,
				Namespace: cr.Namespace,
			},
			Data: map[string][]byte{
				"action_groups.yml":  SecurityContextGenerator("action_groups.yml"),
				"config.yml":         SecurityContextGenerator("config.yml"),
				"internal_users.yml": SecurityContextGenerator("internal_users.yml"),
				"nodes_dn.yml":       SecurityContextGenerator("nodes_dn.yml"),
				"roles.yml":          SecurityContextGenerator("roles.yml"),
				"roles_mapping.yml":  SecurityContextGenerator("roles_mapping.yml"),
				"tenants.yml":        SecurityContextGenerator("tenants.yml"),
				"whitelist.yml":      SecurityContextGenerator("whitelist.yml"),
			},
		}
		_, err = k8sClient.CreateSecret(contextSecret)

		if err != nil {
			return false, err
		}
		return true, nil
	}
	// no need to create random secrets
	return true, nil
}

func SecurityContextGenerator(config string) []byte {
	var value []byte
	if config == "action_groups.yml" {
		value, _ = base64.StdEncoding.DecodeString("X21ldGE6CiAgdHlwZTogImFjdGlvbmdyb3VwcyIKICBjb25maWdfdmVyc2lvbjogMg==")
	} else if config == "config.yml" {
		value, _ = base64.StdEncoding.DecodeString("X21ldGE6CiAgdHlwZTogImNvbmZpZyIKICBjb25maWdfdmVyc2lvbjogIjIiCmNvbmZpZzoKICBkeW5hbWljOgogICAgaHR0cDoKICAgICAgYW5vbnltb3VzX2F1dGhfZW5hYmxlZDogZmFsc2UKICAgIGF1dGhjOgogICAgICBiYXNpY19pbnRlcm5hbF9hdXRoX2RvbWFpbjoKICAgICAgICBodHRwX2VuYWJsZWQ6IHRydWUKICAgICAgICB0cmFuc3BvcnRfZW5hYmxlZDogdHJ1ZQogICAgICAgIG9yZGVyOiAiNCIKICAgICAgICBodHRwX2F1dGhlbnRpY2F0b3I6CiAgICAgICAgICB0eXBlOiBiYXNpYwogICAgICAgICAgY2hhbGxlbmdlOiB0cnVlCiAgICAgICAgYXV0aGVudGljYXRpb25fYmFja2VuZDoKICAgICAgICAgIHR5cGU6IGludGVybg==")
	} else if config == "internal_users.yml" {
		value, _ = base64.StdEncoding.DecodeString("X21ldGE6CiAgdHlwZTogImludGVybmFsdXNlcnMiCiAgY29uZmlnX3ZlcnNpb246IDIKYWRtaW46CiAgaGFzaDogIiQyYSQxMiQybkgubUhCdHdzSDJsZE1sVk0xZGZ1MVpoRWZYR1Z1QnVPOXY4OG9UWjBBNXNSRjhzcUNSTyIKICByZXNlcnZlZDogdHJ1ZQogIGJhY2tlbmRfcm9sZXM6CiAgLSAiYWRtaW4iCiAgZGVzY3JpcHRpb246ICJEZW1vIGFkbWluIHVzZXIiCmRhc2hib2FyZHVzZXI6CiAgaGFzaDogIiQyYSQxMiROMHFmRlhjdWZUeDFYV3F5dXpGLzYualVNRXJSb0tzT3FzZmJSVW1TSzlZRnNrUGVRbUtwYSIKICByZXNlcnZlZDogdHJ1ZQogIGRlc2NyaXB0aW9uOiAiRGVtbyBPcGVuU2VhcmNoIERhc2hib2FyZHMgdXNlciI=")
	} else if config == "nodes_dn.yml" {
		value, _ = base64.StdEncoding.DecodeString("X21ldGE6CiAgdHlwZTogIm5vZGVzZG4iCiAgY29uZmlnX3ZlcnNpb246IDI=")
	} else if config == "roles.yml" {
		value, _ = base64.StdEncoding.DecodeString("X21ldGE6CiAgdHlwZTogInJvbGVzIgogIGNvbmZpZ192ZXJzaW9uOiAyCmRhc2hib2FyZF9yZWFkX29ubHk6CiAgcmVzZXJ2ZWQ6IHRydWUKc2VjdXJpdHlfcmVzdF9hcGlfYWNjZXNzOgogIHJlc2VydmVkOiB0cnVlCiMgQWxsb3dzIHVzZXJzIHRvIHZpZXcgbW9uaXRvcnMsIGRlc3RpbmF0aW9ucyBhbmQgYWxlcnRzCmFsZXJ0aW5nX3JlYWRfYWNjZXNzOgogIHJlc2VydmVkOiB0cnVlCiAgY2x1c3Rlcl9wZXJtaXNzaW9uczoKICAgIC0gJ2NsdXN0ZXI6YWRtaW4vb3BlbmRpc3Ryby9hbGVydGluZy9hbGVydHMvZ2V0JwogICAgLSAnY2x1c3RlcjphZG1pbi9vcGVuZGlzdHJvL2FsZXJ0aW5nL2Rlc3RpbmF0aW9uL2dldCcKICAgIC0gJ2NsdXN0ZXI6YWRtaW4vb3BlbmRpc3Ryby9hbGVydGluZy9tb25pdG9yL2dldCcKICAgIC0gJ2NsdXN0ZXI6YWRtaW4vb3BlbmRpc3Ryby9hbGVydGluZy9tb25pdG9yL3NlYXJjaCcKIyBBbGxvd3MgdXNlcnMgdG8gdmlldyBhbmQgYWNrbm93bGVkZ2UgYWxlcnRzCmFsZXJ0aW5nX2Fja19hbGVydHM6CiAgcmVzZXJ2ZWQ6IHRydWUKICBjbHVzdGVyX3Blcm1pc3Npb25zOgogICAgLSAnY2x1c3RlcjphZG1pbi9vcGVuZGlzdHJvL2FsZXJ0aW5nL2FsZXJ0cy8qJwojIEFsbG93cyB1c2VycyB0byB1c2UgYWxsIGFsZXJ0aW5nIGZ1bmN0aW9uYWxpdHkKYWxlcnRpbmdfZnVsbF9hY2Nlc3M6CiAgcmVzZXJ2ZWQ6IHRydWUKICBjbHVzdGVyX3Blcm1pc3Npb25zOgogICAgLSAnY2x1c3Rlcl9tb25pdG9yJwogICAgLSAnY2x1c3RlcjphZG1pbi9vcGVuZGlzdHJvL2FsZXJ0aW5nLyonCiAgaW5kZXhfcGVybWlzc2lvbnM6CiAgICAtIGluZGV4X3BhdHRlcm5zOgogICAgICAgIC0gJyonCiAgICAgIGFsbG93ZWRfYWN0aW9uczoKICAgICAgICAtICdpbmRpY2VzX21vbml0b3InCiAgICAgICAgLSAnaW5kaWNlczphZG1pbi9hbGlhc2VzL2dldCcKICAgICAgICAtICdpbmRpY2VzOmFkbWluL21hcHBpbmdzL2dldCcKIyBBbGxvdyB1c2VycyB0byByZWFkIEFub21hbHkgRGV0ZWN0aW9uIGRldGVjdG9ycyBhbmQgcmVzdWx0cwphbm9tYWx5X3JlYWRfYWNjZXNzOgogIHJlc2VydmVkOiB0cnVlCiAgY2x1c3Rlcl9wZXJtaXNzaW9uczoKICAgIC0gJ2NsdXN0ZXI6YWRtaW4vb3BlbmRpc3Ryby9hZC9kZXRlY3Rvci9pbmZvJwogICAgLSAnY2x1c3RlcjphZG1pbi9vcGVuZGlzdHJvL2FkL2RldGVjdG9yL3NlYXJjaCcKICAgIC0gJ2NsdXN0ZXI6YWRtaW4vb3BlbmRpc3Ryby9hZC9kZXRlY3RvcnMvZ2V0JwogICAgLSAnY2x1c3RlcjphZG1pbi9vcGVuZGlzdHJvL2FkL3Jlc3VsdC9zZWFyY2gnCiAgICAtICdjbHVzdGVyOmFkbWluL29wZW5kaXN0cm8vYWQvdGFza3Mvc2VhcmNoJwogICAgLSAnY2x1c3RlcjphZG1pbi9vcGVuZGlzdHJvL2FkL2RldGVjdG9yL3ZhbGlkYXRlJwogICAgLSAnY2x1c3RlcjphZG1pbi9vcGVuZGlzdHJvL2FkL3Jlc3VsdC90b3BBbm9tYWxpZXMnCiMgQWxsb3dzIHVzZXJzIHRvIHVzZSBhbGwgQW5vbWFseSBEZXRlY3Rpb24gZnVuY3Rpb25hbGl0eQphbm9tYWx5X2Z1bGxfYWNjZXNzOgogIHJlc2VydmVkOiB0cnVlCiAgY2x1c3Rlcl9wZXJtaXNzaW9uczoKICAgIC0gJ2NsdXN0ZXJfbW9uaXRvcicKICAgIC0gJ2NsdXN0ZXI6YWRtaW4vb3BlbmRpc3Ryby9hZC8qJwogIGluZGV4X3Blcm1pc3Npb25zOgogICAgLSBpbmRleF9wYXR0ZXJuczoKICAgICAgICAtICcqJwogICAgICBhbGxvd2VkX2FjdGlvbnM6CiAgICAgICAgLSAnaW5kaWNlc19tb25pdG9yJwogICAgICAgIC0gJ2luZGljZXM6YWRtaW4vYWxpYXNlcy9nZXQnCiAgICAgICAgLSAnaW5kaWNlczphZG1pbi9tYXBwaW5ncy9nZXQnCiMgQWxsb3dzIHVzZXJzIHRvIHJlYWQgTm90ZWJvb2tzCm5vdGVib29rc19yZWFkX2FjY2VzczoKICByZXNlcnZlZDogdHJ1ZQogIGNsdXN0ZXJfcGVybWlzc2lvbnM6CiAgICAtICdjbHVzdGVyOmFkbWluL29wZW5kaXN0cm8vbm90ZWJvb2tzL2xpc3QnCiAgICAtICdjbHVzdGVyOmFkbWluL29wZW5kaXN0cm8vbm90ZWJvb2tzL2dldCcKIyBBbGxvd3MgdXNlcnMgdG8gYWxsIE5vdGVib29rcyBmdW5jdGlvbmFsaXR5Cm5vdGVib29rc19mdWxsX2FjY2VzczoKICByZXNlcnZlZDogdHJ1ZQogIGNsdXN0ZXJfcGVybWlzc2lvbnM6CiAgICAtICdjbHVzdGVyOmFkbWluL29wZW5kaXN0cm8vbm90ZWJvb2tzL2NyZWF0ZScKICAgIC0gJ2NsdXN0ZXI6YWRtaW4vb3BlbmRpc3Ryby9ub3RlYm9va3MvdXBkYXRlJwogICAgLSAnY2x1c3RlcjphZG1pbi9vcGVuZGlzdHJvL25vdGVib29rcy9kZWxldGUnCiAgICAtICdjbHVzdGVyOmFkbWluL29wZW5kaXN0cm8vbm90ZWJvb2tzL2dldCcKICAgIC0gJ2NsdXN0ZXI6YWRtaW4vb3BlbmRpc3Ryby9ub3RlYm9va3MvbGlzdCcKIyBBbGxvd3MgdXNlcnMgdG8gcmVhZCBvYnNlcnZhYmlsaXR5IG9iamVjdHMKb2JzZXJ2YWJpbGl0eV9yZWFkX2FjY2VzczoKICByZXNlcnZlZDogdHJ1ZQogIGNsdXN0ZXJfcGVybWlzc2lvbnM6CiAgICAtICdjbHVzdGVyOmFkbWluL29wZW5zZWFyY2gvb2JzZXJ2YWJpbGl0eS9nZXQnCiMgQWxsb3dzIHVzZXJzIHRvIGFsbCBPYnNlcnZhYmlsaXR5IGZ1bmN0aW9uYWxpdHkKb2JzZXJ2YWJpbGl0eV9mdWxsX2FjY2VzczoKICByZXNlcnZlZDogdHJ1ZQogIGNsdXN0ZXJfcGVybWlzc2lvbnM6CiAgICAtICdjbHVzdGVyOmFkbWluL29wZW5zZWFyY2gvb2JzZXJ2YWJpbGl0eS9jcmVhdGUnCiAgICAtICdjbHVzdGVyOmFkbWluL29wZW5zZWFyY2gvb2JzZXJ2YWJpbGl0eS91cGRhdGUnCiAgICAtICdjbHVzdGVyOmFkbWluL29wZW5zZWFyY2gvb2JzZXJ2YWJpbGl0eS9kZWxldGUnCiAgICAtICdjbHVzdGVyOmFkbWluL29wZW5zZWFyY2gvb2JzZXJ2YWJpbGl0eS9nZXQnCiMgQWxsb3dzIHVzZXJzIHRvIHJlYWQgYW5kIGRvd25sb2FkIFJlcG9ydHMKcmVwb3J0c19pbnN0YW5jZXNfcmVhZF9hY2Nlc3M6CiAgcmVzZXJ2ZWQ6IHRydWUKICBjbHVzdGVyX3Blcm1pc3Npb25zOgogICAgLSAnY2x1c3RlcjphZG1pbi9vcGVuZGlzdHJvL3JlcG9ydHMvaW5zdGFuY2UvbGlzdCcKICAgIC0gJ2NsdXN0ZXI6YWRtaW4vb3BlbmRpc3Ryby9yZXBvcnRzL2luc3RhbmNlL2dldCcKICAgIC0gJ2NsdXN0ZXI6YWRtaW4vb3BlbmRpc3Ryby9yZXBvcnRzL21lbnUvZG93bmxvYWQnCiMgQWxsb3dzIHVzZXJzIHRvIHJlYWQgYW5kIGRvd25sb2FkIFJlcG9ydHMgYW5kIFJlcG9ydC1kZWZpbml0aW9ucwpyZXBvcnRzX3JlYWRfYWNjZXNzOgogIHJlc2VydmVkOiB0cnVlCiAgY2x1c3Rlcl9wZXJtaXNzaW9uczoKICAgIC0gJ2NsdXN0ZXI6YWRtaW4vb3BlbmRpc3Ryby9yZXBvcnRzL2RlZmluaXRpb24vZ2V0JwogICAgLSAnY2x1c3RlcjphZG1pbi9vcGVuZGlzdHJvL3JlcG9ydHMvZGVmaW5pdGlvbi9saXN0JwogICAgLSAnY2x1c3RlcjphZG1pbi9vcGVuZGlzdHJvL3JlcG9ydHMvaW5zdGFuY2UvbGlzdCcKICAgIC0gJ2NsdXN0ZXI6YWRtaW4vb3BlbmRpc3Ryby9yZXBvcnRzL2luc3RhbmNlL2dldCcKICAgIC0gJ2NsdXN0ZXI6YWRtaW4vb3BlbmRpc3Ryby9yZXBvcnRzL21lbnUvZG93bmxvYWQnCiMgQWxsb3dzIHVzZXJzIHRvIGFsbCBSZXBvcnRzIGZ1bmN0aW9uYWxpdHkKcmVwb3J0c19mdWxsX2FjY2VzczoKICByZXNlcnZlZDogdHJ1ZQogIGNsdXN0ZXJfcGVybWlzc2lvbnM6CiAgICAtICdjbHVzdGVyOmFkbWluL29wZW5kaXN0cm8vcmVwb3J0cy9kZWZpbml0aW9uL2NyZWF0ZScKICAgIC0gJ2NsdXN0ZXI6YWRtaW4vb3BlbmRpc3Ryby9yZXBvcnRzL2RlZmluaXRpb24vdXBkYXRlJwogICAgLSAnY2x1c3RlcjphZG1pbi9vcGVuZGlzdHJvL3JlcG9ydHMvZGVmaW5pdGlvbi9vbl9kZW1hbmQnCiAgICAtICdjbHVzdGVyOmFkbWluL29wZW5kaXN0cm8vcmVwb3J0cy9kZWZpbml0aW9uL2RlbGV0ZScKICAgIC0gJ2NsdXN0ZXI6YWRtaW4vb3BlbmRpc3Ryby9yZXBvcnRzL2RlZmluaXRpb24vZ2V0JwogICAgLSAnY2x1c3RlcjphZG1pbi9vcGVuZGlzdHJvL3JlcG9ydHMvZGVmaW5pdGlvbi9saXN0JwogICAgLSAnY2x1c3RlcjphZG1pbi9vcGVuZGlzdHJvL3JlcG9ydHMvaW5zdGFuY2UvbGlzdCcKICAgIC0gJ2NsdXN0ZXI6YWRtaW4vb3BlbmRpc3Ryby9yZXBvcnRzL2luc3RhbmNlL2dldCcKICAgIC0gJ2NsdXN0ZXI6YWRtaW4vb3BlbmRpc3Ryby9yZXBvcnRzL21lbnUvZG93bmxvYWQnCiMgQWxsb3dzIHVzZXJzIHRvIHVzZSBhbGwgYXN5bmNocm9ub3VzLXNlYXJjaCBmdW5jdGlvbmFsaXR5CmFzeW5jaHJvbm91c19zZWFyY2hfZnVsbF9hY2Nlc3M6CiAgcmVzZXJ2ZWQ6IHRydWUKICBjbHVzdGVyX3Blcm1pc3Npb25zOgogICAgLSAnY2x1c3RlcjphZG1pbi9vcGVuZGlzdHJvL2FzeW5jaHJvbm91c19zZWFyY2gvKicKICBpbmRleF9wZXJtaXNzaW9uczoKICAgIC0gaW5kZXhfcGF0dGVybnM6CiAgICAgICAgLSAnKicKICAgICAgYWxsb3dlZF9hY3Rpb25zOgogICAgICAgIC0gJ2luZGljZXM6ZGF0YS9yZWFkL3NlYXJjaConCiMgQWxsb3dzIHVzZXJzIHRvIHJlYWQgc3RvcmVkIGFzeW5jaHJvbm91cy1zZWFyY2ggcmVzdWx0cwphc3luY2hyb25vdXNfc2VhcmNoX3JlYWRfYWNjZXNzOgogIHJlc2VydmVkOiB0cnVlCiAgY2x1c3Rlcl9wZXJtaXNzaW9uczoKICAgIC0gJ2NsdXN0ZXI6YWRtaW4vb3BlbmRpc3Ryby9hc3luY2hyb25vdXNfc2VhcmNoL2dldCcKIyBBbGxvd3MgdXNlciB0byB1c2UgYWxsIGluZGV4X21hbmFnZW1lbnQgYWN0aW9ucyAtIGlzbSBwb2xpY2llcywgcm9sbHVwcywgdHJhbnNmb3JtcwppbmRleF9tYW5hZ2VtZW50X2Z1bGxfYWNjZXNzOgogIHJlc2VydmVkOiB0cnVlCiAgY2x1c3Rlcl9wZXJtaXNzaW9uczoKICAgIC0gImNsdXN0ZXI6YWRtaW4vb3BlbmRpc3Ryby9pc20vKiIKICAgIC0gImNsdXN0ZXI6YWRtaW4vb3BlbmRpc3Ryby9yb2xsdXAvKiIKICAgIC0gImNsdXN0ZXI6YWRtaW4vb3BlbmRpc3Ryby90cmFuc2Zvcm0vKiIKICBpbmRleF9wZXJtaXNzaW9uczoKICAgIC0gaW5kZXhfcGF0dGVybnM6CiAgICAgICAgLSAnKicKICAgICAgYWxsb3dlZF9hY3Rpb25zOgogICAgICAgIC0gJ2luZGljZXM6YWRtaW4vb3BlbnNlYXJjaC9pc20vKicKIyBBbGxvd3MgdXNlcnMgdG8gdXNlIGFsbCBjcm9zcyBjbHVzdGVyIHJlcGxpY2F0aW9uIGZ1bmN0aW9uYWxpdHkgYXQgbGVhZGVyIGNsdXN0ZXIKY3Jvc3NfY2x1c3Rlcl9yZXBsaWNhdGlvbl9sZWFkZXJfZnVsbF9hY2Nlc3M6CiAgcmVzZXJ2ZWQ6IHRydWUKICBpbmRleF9wZXJtaXNzaW9uczoKICAgIC0gaW5kZXhfcGF0dGVybnM6CiAgICAgICAgLSAnKicKICAgICAgYWxsb3dlZF9hY3Rpb25zOgogICAgICAgIC0gImluZGljZXM6YWRtaW4vcGx1Z2lucy9yZXBsaWNhdGlvbi9pbmRleC9zZXR1cC92YWxpZGF0ZSIKICAgICAgICAtICJpbmRpY2VzOmRhdGEvcmVhZC9wbHVnaW5zL3JlcGxpY2F0aW9uL2NoYW5nZXMiCiAgICAgICAgLSAiaW5kaWNlczpkYXRhL3JlYWQvcGx1Z2lucy9yZXBsaWNhdGlvbi9maWxlX2NodW5rIgojIEFsbG93cyB1c2VycyB0byB1c2UgYWxsIGNyb3NzIGNsdXN0ZXIgcmVwbGljYXRpb24gZnVuY3Rpb25hbGl0eSBhdCBmb2xsb3dlciBjbHVzdGVyCmNyb3NzX2NsdXN0ZXJfcmVwbGljYXRpb25fZm9sbG93ZXJfZnVsbF9hY2Nlc3M6CiAgcmVzZXJ2ZWQ6IHRydWUKICBjbHVzdGVyX3Blcm1pc3Npb25zOgogICAgLSAiY2x1c3RlcjphZG1pbi9wbHVnaW5zL3JlcGxpY2F0aW9uL2F1dG9mb2xsb3cvdXBkYXRlIgogIGluZGV4X3Blcm1pc3Npb25zOgogICAgLSBpbmRleF9wYXR0ZXJuczoKICAgICAgICAtICcqJwogICAgICBhbGxvd2VkX2FjdGlvbnM6CiAgICAgICAgLSAiaW5kaWNlczphZG1pbi9wbHVnaW5zL3JlcGxpY2F0aW9uL2luZGV4L3NldHVwL3ZhbGlkYXRlIgogICAgICAgIC0gImluZGljZXM6ZGF0YS93cml0ZS9wbHVnaW5zL3JlcGxpY2F0aW9uL2NoYW5nZXMiCiAgICAgICAgLSAiaW5kaWNlczphZG1pbi9wbHVnaW5zL3JlcGxpY2F0aW9uL2luZGV4L3N0YXJ0IgogICAgICAgIC0gImluZGljZXM6YWRtaW4vcGx1Z2lucy9yZXBsaWNhdGlvbi9pbmRleC9wYXVzZSIKICAgICAgICAtICJpbmRpY2VzOmFkbWluL3BsdWdpbnMvcmVwbGljYXRpb24vaW5kZXgvcmVzdW1lIgogICAgICAgIC0gImluZGljZXM6YWRtaW4vcGx1Z2lucy9yZXBsaWNhdGlvbi9pbmRleC9zdG9wIgogICAgICAgIC0gImluZGljZXM6YWRtaW4vcGx1Z2lucy9yZXBsaWNhdGlvbi9pbmRleC91cGRhdGUiCiAgICAgICAgLSAiaW5kaWNlczphZG1pbi9wbHVnaW5zL3JlcGxpY2F0aW9uL2luZGV4L3N0YXR1c19jaGVjayI=")
	} else if config == "roles_mapping.yml" {
		value, _ = base64.StdEncoding.DecodeString("X21ldGE6CiAgdHlwZTogInJvbGVzbWFwcGluZyIKICBjb25maWdfdmVyc2lvbjogMgphbGxfYWNjZXNzOgogIHJlc2VydmVkOiBmYWxzZQogIGJhY2tlbmRfcm9sZXM6CiAgLSAiYWRtaW4iCiAgZGVzY3JpcHRpb246ICJNYXBzIGFkbWluIHRvIGFsbF9hY2Nlc3MiCm93bl9pbmRleDoKICByZXNlcnZlZDogZmFsc2UKICB1c2VyczoKICAtICIqIgogIGRlc2NyaXB0aW9uOiAiQWxsb3cgZnVsbCBhY2Nlc3MgdG8gYW4gaW5kZXggbmFtZWQgbGlrZSB0aGUgdXNlcm5hbWUiCnJlYWRhbGw6CiAgcmVzZXJ2ZWQ6IGZhbHNlCiAgYmFja2VuZF9yb2xlczoKICAtICJyZWFkYWxsIgptYW5hZ2Vfc25hcHNob3RzOgogIHJlc2VydmVkOiBmYWxzZQogIGJhY2tlbmRfcm9sZXM6CiAgLSAic25hcHNob3RyZXN0b3JlIgpkYXNoYm9hcmRfc2VydmVyOgogIHJlc2VydmVkOiB0cnVlCiAgdXNlcnM6CiAgLSAiZGFzaGJvYXJkdXNlciI=")
	} else if config == "tenants.yml" {
		value, _ = base64.StdEncoding.DecodeString("X21ldGE6CiAgdHlwZTogInRlbmFudHMiCiAgY29uZmlnX3ZlcnNpb246IDI=")
	} else if config == "whitelist.yml" {
		value, _ = base64.StdEncoding.DecodeString("X21ldGE6CiAgdHlwZTogIndoaXRlbGlzdCIKICBjb25maWdfdmVyc2lvbjogMg==")
	}
	return value
}

func UsernameAndPassword(k8sClient k8s.K8sClient, cr *opsterv1.OpenSearchCluster) (string, string, error) {
	if cr.Spec.Security != nil && cr.Spec.Security.Config != nil && cr.Spec.Security.Config.AdminCredentialsSecret.Name != "" {
		// Read credentials from secret
		credentialsSecret, err := k8sClient.GetSecret(cr.Spec.Security.Config.AdminCredentialsSecret.Name, cr.Namespace)
		if err != nil {
			return "", "", err
		}
		username, usernameExists := credentialsSecret.Data["username"]
		password, passwordExists := credentialsSecret.Data["password"]
		if !usernameExists || !passwordExists {
			return "", "", errors.New("username or password field missing")
		}
		return string(username), string(password), nil
	} else {
		// Use default demo credentials
		return "admin", "admin", nil
	}
}

func GetByDescriptionAndComponent(left opsterv1.ComponentStatus, right opsterv1.ComponentStatus) (opsterv1.ComponentStatus, bool) {
	if left.Description == right.Description && left.Component == right.Component {
		return left, true
	}
	return right, false
}

func GetByComponent(left opsterv1.ComponentStatus, right opsterv1.ComponentStatus) (opsterv1.ComponentStatus, bool) {
	if left.Component == right.Component {
		return left, true
	}
	return right, false
}

func MergeConfigs(left map[string]string, right map[string]string) map[string]string {
	if left == nil {
		return right
	}
	for k, v := range right {
		left[k] = v
	}
	return left
}

// Return the keys of the input map in sorted order
// Can be used if you want to iterate over a map but have a stable order
func SortedKeys(input map[string]string) []string {
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// SortedJsonKeys helps to sort JSON object keys
// E.g. if API returns unsorted JSON object like this: {"resp": {"b": "2", "a": "1"}}
// this function could sort it and return {"resp": {"a": "1", "b": "2"}}
// This is useful for comparing Opensearch CRD objects and API responses
func SortedJsonKeys(obj *apiextensionsv1.JSON) (*apiextensionsv1.JSON, error) {
	m := make(map[string]interface{})
	if err := json.Unmarshal(obj.Raw, &m); err != nil {
		return nil, err
	}
	rawBytes, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return &apiextensionsv1.JSON{Raw: rawBytes}, err
}

func ResolveClusterManagerRole(ver string) string {
	masterRole := "master"
	osVer, err := version.NewVersion(ver)

	clusterManagerVer, _ := version.NewVersion("2.0.0")
	if err == nil && osVer.GreaterThanOrEqual(clusterManagerVer) {
		masterRole = "cluster_manager"
	}
	return masterRole
}

// Map any cluster roles that have changed between major OpenSearch versions
func MapClusterRole(role string, ver string) string {
	osVer, err := version.NewVersion(ver)
	if err != nil {
		return role
	}
	clusterManagerVer, _ := version.NewVersion("2.0.0")
	is2XVersion := osVer.GreaterThanOrEqual(clusterManagerVer)
	if role == "master" && is2XVersion {
		return "cluster_manager"
	} else if role == "cluster_manager" && !is2XVersion {
		return "master"
	} else {
		return role
	}
}

func MapClusterRoles(roles []string, version string) []string {
	mapped_roles := []string{}
	for _, role := range roles {
		mapped_roles = append(mapped_roles, MapClusterRole(role, version))
	}
	return mapped_roles
}

// Get leftSlice strings not in rightSlice
func DiffSlice(leftSlice, rightSlice []string) []string {
	// diff := []string{}
	var diff []string

	for _, leftSliceString := range leftSlice {
		if !ContainsString(rightSlice, leftSliceString) {
			diff = append(diff, leftSliceString)
		}
	}
	return diff
}

// Count the number of pods running and ready and not terminating for a given nodePool
func CountRunningPodsForNodePool(k8sClient k8s.K8sClient, cr *opsterv1.OpenSearchCluster, nodePool *opsterv1.NodePool) (int, error) {
	// Constrict selector from labels
	clusterReq, err := labels.NewRequirement(ClusterLabel, selection.Equals, []string{cr.ObjectMeta.Name})
	if err != nil {
		return 0, err
	}
	componentReq, err := labels.NewRequirement(NodePoolLabel, selection.Equals, []string{nodePool.Component})
	if err != nil {
		return 0, err
	}
	selector := labels.NewSelector()
	selector = selector.Add(*clusterReq, *componentReq)
	// List pods matching selector
	list, err := k8sClient.ListPods(&client.ListOptions{Namespace: cr.Namespace, LabelSelector: selector})
	if err != nil {
		return 0, err
	}
	// Count pods that are ready
	numReadyPods := 0
	for _, pod := range list.Items {
		// If DeletionTimestamp is set the pod is terminating
		podReady := pod.ObjectMeta.DeletionTimestamp == nil
		// Count the pod as not ready if one of its containers is not running or not ready
		for _, container := range pod.Status.ContainerStatuses {
			if !container.Ready || container.State.Running == nil {
				podReady = false
			}
		}
		if podReady {
			numReadyPods += 1
		}
	}
	return numReadyPods, nil
}

// Count the number of PVCs created for the given NodePool
func CountPVCsForNodePool(k8sClient k8s.K8sClient, cr *opsterv1.OpenSearchCluster, nodePool *opsterv1.NodePool) (int, error) {
	clusterReq, err := labels.NewRequirement(ClusterLabel, selection.Equals, []string{cr.ObjectMeta.Name})
	if err != nil {
		return 0, err
	}
	componentReq, err := labels.NewRequirement(NodePoolLabel, selection.Equals, []string{nodePool.Component})
	if err != nil {
		return 0, err
	}
	selector := labels.NewSelector()
	selector = selector.Add(*clusterReq, *componentReq)
	list, err := k8sClient.ListPVCs(&client.ListOptions{Namespace: cr.Namespace, LabelSelector: selector})
	if err != nil {
		return 0, err
	}
	return len(list.Items), nil
}

// Delete a STS with cascade=orphan and wait until it is actually deleted from the kubernetes API
func WaitForSTSDelete(k8sClient k8s.K8sClient, obj *appsv1.StatefulSet) error {
	if err := k8sClient.DeleteStatefulSet(obj, true); err != nil {
		return err
	}
	for i := 1; i <= stsUpdateWaitTime/updateStepTime; i++ {
		_, err := k8sClient.GetStatefulSet(obj.Name, obj.Namespace)
		if err != nil {
			return nil
		}
		time.Sleep(time.Second * updateStepTime)
	}
	return fmt.Errorf("failed to delete STS")
}

// Wait for max 30s until a STS has at least the given number of replicas
func WaitForSTSReplicas(k8sClient k8s.K8sClient, obj *appsv1.StatefulSet, replicas int32) error {
	for i := 1; i <= stsUpdateWaitTime/updateStepTime; i++ {
		existing, err := k8sClient.GetStatefulSet(obj.Name, obj.Namespace)
		if err == nil {
			if existing.Status.Replicas >= replicas {
				return nil
			}
		}
		time.Sleep(time.Second * updateStepTime)
	}
	return fmt.Errorf("failed to wait for replicas")
}

// Wait for max 30s until a STS has a normal status (CurrentRevision != "")
func WaitForSTSStatus(k8sClient k8s.K8sClient, obj *appsv1.StatefulSet) (*appsv1.StatefulSet, error) {
	for i := 1; i <= stsUpdateWaitTime/updateStepTime; i++ {
		existing, err := k8sClient.GetStatefulSet(obj.Name, obj.Namespace)
		if err == nil {
			if existing.Status.CurrentRevision != "" {
				return &existing, nil
			}
		}
		time.Sleep(time.Second * updateStepTime)
	}
	return nil, fmt.Errorf("failed to wait for STS")
}

// GetSTSForNodePool returns the corresponding sts for a given nodePool and cluster name
func GetSTSForNodePool(k8sClient k8s.K8sClient, nodePool opsterv1.NodePool, clusterName, clusterNamespace string) (*appsv1.StatefulSet, error) {
	stsName := clusterName + "-" + nodePool.Component
	existing, err := k8sClient.GetStatefulSet(stsName, clusterNamespace)
	return &existing, err
}

// DeleteSTSForNodePool deletes the sts for the corresponding nodePool
func DeleteSTSForNodePool(k8sClient k8s.K8sClient, nodePool opsterv1.NodePool, clusterName, clusterNamespace string) error {
	sts, err := GetSTSForNodePool(k8sClient, nodePool, clusterName, clusterNamespace)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	if err := k8sClient.DeleteStatefulSet(sts, false); err != nil {
		return err
	}

	// Wait for the STS to actually be deleted
	for i := 1; i <= stsUpdateWaitTime/updateStepTime; i++ {
		_, err := k8sClient.GetStatefulSet(sts.Name, sts.Namespace)
		if err != nil {
			return nil
		}
		time.Sleep(time.Second * updateStepTime)
	}

	return fmt.Errorf("failed to delete STS for nodepool %s", nodePool.Component)
}

// DeleteSecurityUpdateJob deletes the securityconfig update job
func DeleteSecurityUpdateJob(k8sClient k8s.K8sClient, clusterName, clusterNamespace string) error {
	jobName := clusterName + "-securityconfig-update"
	job, err := k8sClient.GetJob(jobName, clusterNamespace)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	return k8sClient.DeleteJob(&job)
}

func HasDataRole(nodePool *opsterv1.NodePool) bool {
	return ContainsString(nodePool.Roles, "data")
}

func HasManagerRole(nodePool *opsterv1.NodePool) bool {
	return ContainsString(nodePool.Roles, "master") || ContainsString(nodePool.Roles, "cluster_manager")
}

func RemoveDuplicateStrings(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

// Compares whether v1 is LessThan v2
func CompareVersions(v1 string, v2 string) bool {
	ver1, err := version.NewVersion(v1)
	ver2, _ := version.NewVersion(v2)
	return err == nil && ver1.LessThan(ver2)
}

func ComposePDB(cr *opsterv1.OpenSearchCluster, nodepool *opsterv1.NodePool) policyv1.PodDisruptionBudget {
	matchLabels := map[string]string{
		ClusterLabel:  cr.Name,
		NodePoolLabel: nodepool.Component,
	}
	newpdb := policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Name + "-" + nodepool.Component + "-pdb",
			Namespace: cr.Namespace,
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MinAvailable:   nodepool.Pdb.MinAvailable,
			MaxUnavailable: nodepool.Pdb.MaxUnavailable,
			Selector: &metav1.LabelSelector{
				MatchLabels: matchLabels,
			},
		},
	}
	return newpdb
}

func CalculateJvmHeapSize(nodePool *opsterv1.NodePool) string {
	jvmHeapSizeTemplate := "-Xmx%s -Xms%s"

	if nodePool.Jvm == "" {
		memoryLimit := nodePool.Resources.Requests.Memory()

		// Memory request is not present
		if memoryLimit.IsZero() {
			return fmt.Sprintf(jvmHeapSizeTemplate, "512M", "512M")
		}

		// Set Java Heap size to half of the node pool memory size
		megabytes := float64((memoryLimit.Value() / 2) / 1024.0 / 1024.0)

		heapSize := fmt.Sprintf("%vM", megabytes)
		return fmt.Sprintf(jvmHeapSizeTemplate, heapSize, heapSize)
	}

	return nodePool.Jvm
}

func IsUpgradeInProgress(status opsterv1.ClusterStatus) bool {
	componentStatus := opsterv1.ComponentStatus{
		Component: "Upgrader",
	}
	foundStatus := FindAllPartial(status.ComponentsStatus, componentStatus, GetByComponent)
	inProgress := false

	// check all statuses if any of the nodepools are still in progress or pending
	for i := 0; i < len(foundStatus); i++ {
		if foundStatus[i].Status != "Upgraded" && foundStatus[i].Status != "Finished" {
			inProgress = true
		}
	}

	return inProgress
}

func ReplicaHostName(currentSts appsv1.StatefulSet, repNum int32) string {
	return fmt.Sprintf("%s-%d", currentSts.ObjectMeta.Name, repNum)
}

func WorkingPodForRollingRestart(k8sClient k8s.K8sClient, sts *appsv1.StatefulSet) (string, error) {
	// If there are potentially mixed revisions we need to check each pod
	podWithOlderRevision, err := GetPodWithOlderRevision(k8sClient, sts)
	if err != nil {
		return "", err
	}
	if podWithOlderRevision != nil {
		return podWithOlderRevision.Name, nil
	}
	return "", errors.New("unable to calculate the working pod for rolling restart")
}

// DeleteStuckPodWithOlderRevision deletes the crashed pod only if there is any update in StatefulSet.
func DeleteStuckPodWithOlderRevision(k8sClient k8s.K8sClient, sts *appsv1.StatefulSet) error {
	podWithOlderRevision, err := GetPodWithOlderRevision(k8sClient, sts)
	if err != nil {
		return err
	}
	if podWithOlderRevision != nil {
		for _, container := range podWithOlderRevision.Status.ContainerStatuses {
			// If any container is getting crashed, restart it by deleting the pod so that new update in sts can take place.
			if !container.Ready && container.State.Waiting != nil && container.State.Waiting.Reason == "CrashLoopBackOff" {
				return k8sClient.DeletePod(&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      podWithOlderRevision.Name,
						Namespace: sts.Namespace,
					},
				})
			}
		}
	}
	return nil
}

// GetPodWithOlderRevision fetches the pod that is not having the updated revision.
func GetPodWithOlderRevision(k8sClient k8s.K8sClient, sts *appsv1.StatefulSet) (*corev1.Pod, error) {
	for i := int32(0); i < lo.FromPtrOr(sts.Spec.Replicas, 1); i++ {
		podName := ReplicaHostName(*sts, i)
		pod, err := k8sClient.GetPod(podName, sts.Namespace)
		if err != nil {
			return nil, err
		}
		podRevision, ok := pod.Labels[stsRevisionLabel]
		if !ok {
			return nil, fmt.Errorf("pod %s has no revision label", podName)
		}
		if podRevision != sts.Status.UpdateRevision {
			return &pod, nil
		}
	}
	return nil, nil
}

func GetDashboardsDeployment(k8sClient k8s.K8sClient, clusterName, clusterNamespace string) (*appsv1.Deployment, error) {
	deploy, err := k8sClient.GetDeployment(clusterName+"-dashboards", clusterNamespace)
	return &deploy, err
}

// DeleteDashboardsDeployment deletes the OSD deployment along with all its pods
func DeleteDashboardsDeployment(k8sClient k8s.K8sClient, clusterName, clusterNamespace string) error {
	deploy, err := GetDashboardsDeployment(k8sClient, clusterName, clusterNamespace)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	if err := k8sClient.DeleteDeployment(deploy, false); err != nil {
		return err
	}

	// Wait for Dashboards deploy to delete
	// We can use the same waiting time for sts as both have same termination grace period
	for i := 1; i <= stsUpdateWaitTime/updateStepTime; i++ {
		_, err := k8sClient.GetDeployment(deploy.Name, clusterNamespace)
		if err != nil {
			return nil
		}
		time.Sleep(time.Second * updateStepTime)
	}

	return fmt.Errorf("failed to delete dashboards deployment for cluster %s", clusterName)
}

func DiscoverRandomAdminSecret(k8sClient k8s.K8sClient, cr *opsterv1.OpenSearchCluster) (*corev1.Secret, error) {
	secret, err := k8sClient.GetSecret(cr.Spec.Security.Config.AdminCredentialsSecret.Name, cr.Namespace)
	return &secret, err
}

func DiscoverRandomContextSecret(k8sClient k8s.K8sClient, cr *opsterv1.OpenSearchCluster) (*corev1.Secret, error) {
	secret, err := k8sClient.GetSecret(cr.Spec.Security.Config.SecurityconfigSecret.Name, cr.Namespace)
	return &secret, err
}
