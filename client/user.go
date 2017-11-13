package client

import (
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/aws/awserr"
)

type User struct {
	Name     string
	AccessID []string
	Certs    []string
	Password bool
	MFA      [1]string
	//VMFA []string
	Policies []string
	Groups   []string
}

func PopulateInformation(username *User) {

	checkUser := getUserInfo(username)
	if !checkUser{
		return
	}
	accessKey(username)
	certificate(username)
	profile(username)
	mfa(username)
	group(username)
	policies(username)
	if !dryrun{
		removeUser(username)
	}
}

func getUserInfo(user *User) bool{
	log.Debugf("Checking if %s exists",user.Name)
	results, err := svc.GetUser(&iam.GetUserInput{
		UserName: &user.Name,
	})
	log.Debugf("User: %s API: %s",user.Name,results)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == iam.ErrCodeNoSuchEntityException {
				log.Infof("Unable to find User: %s",user.Name)
				log.Debugf("User: %s, API:%s",user.Name,results)
				return false
			}
		}
		log.Errorf("User: %s MSG:%s",user.Name,err)
		return false
	}else{

		if *results.User.UserName == user.Name {
			return true
		}

	}

	return false
}

func accessKey(user *User) {

	results, err := svc.ListAccessKeys(&iam.ListAccessKeysInput{
		UserName: &user.Name,
	})
	if err != nil {
		log.Errorf("User: %s MSG: %s", user.Name, err)
	} else {
		log.Debugf("Querying AccessKeys User %s: Result: %s", user.Name, results)
		user.AccessID = make([]string, len(results.AccessKeyMetadata))
		for i, k := range results.AccessKeyMetadata {
			user.AccessID[i] = *k.AccessKeyId
			log.Infof("Get User: %s AccessKeys: %s", user.Name, *k.AccessKeyId)
			if !dryrun {
				log.Infof("Removing User: %s, AccessKey: %s", user.Name, *k.AccessKeyId)
				result, err := svc.DeleteAccessKey(&iam.DeleteAccessKeyInput{
					AccessKeyId: k.AccessKeyId,
					UserName:    &user.Name,
				})
				if err != nil {
					log.Errorf("User: %s MSG: %s", user.Name, err)
				} else {
					log.Debugf("Removing User:%s , AccessKeyId: %s API Result: %s", user.Name, *k.AccessKeyId, result)
				}

			} else {
				log.Infof("Removing User:%s, AccessKey: %s (DRYRUN)", user.Name, *k.AccessKeyId)
			}

		}
	}
}

func certificate(user *User) {

	results, err := svc.ListSigningCertificates(&iam.ListSigningCertificatesInput{
		UserName: &user.Name,
	})
	if err != nil {
		log.Errorf("User: %s MSG: %s", user.Name, err)
	} else {
		//log.Debugf("Querying Certificate User %s: Result: %s",user.Name,results)
		user.Certs = make([]string, len(results.Certificates))
		for i, k := range results.Certificates {
			user.Certs[i] = *k.CertificateId
			log.Infof("Get User: %s Certificate: %s", user.Name, *k.CertificateId)
			if !dryrun {
				log.Infof("Removing User: %s, AccessKey: %s", user.Name, *k.CertificateId)
				result, err := svc.DeleteSigningCertificate(&iam.DeleteSigningCertificateInput{
					CertificateId: k.CertificateId,
					UserName:      &user.Name,
				})
				if err != nil {
					log.Errorf("User: %s MSG: %s", user.Name, err)
				} else {
					log.Debugf("Removing User:%s , Certificate: %s API Result: %s", user.Name, *k.CertificateId, result)
				}

			} else {
				log.Infof("Removing User:%s, Certificate: %s (DRYRUN)", user.Name, *k.CertificateId)
			}

		}
	}

}

func profile(user *User) {

	results, err := svc.GetLoginProfile(&iam.GetLoginProfileInput{
		UserName: &user.Name,
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == iam.ErrCodeNoSuchEntityException {

				user.Password = false
				log.Infof("User: %s ConsolePassword: %t", user.Name, user.Password)

			} else {
				log.Errorf("User: %s MSG: %s", user.Name, err)

			}
			return
		}

	}
	log.Debugf("Querying Login Profile User %s: Result: %s", user.Name, results)
	log.Infof("User %s ConsolePassword: %t", user.Name, user.Password)
	if !dryrun {
		result, err := svc.DeleteLoginProfile(&iam.DeleteLoginProfileInput{
			UserName: &user.Name,
		})
		if err != nil {
			log.Errorf("User: %s MSG: %s", user.Name, err)
		} else {
			log.Debugf("Removing User:%s , ConsolePassword: %b API Result: %s", user.Name, user.Password, result)
		}
	} else {
		log.Infof("Removing User:%s, ConsolePassword: %t (DRYRUN)", user.Name, user.Password)
	}

}

func mfa(user *User) {

	result, err := svc.ListMFADevices(&iam.ListMFADevicesInput{
		UserName: &user.Name,
	})
	if err != nil {
		log.Error("User %s : MSG: %s", user.Name, err)
	} else {
		log.Debugf("Querying MFA User %s: Result: %s", user.Name, result)
		if result.MFADevices != nil {
			user.MFA[0] = *result.MFADevices[0].SerialNumber
			if !dryrun {
				result, err := svc.DeactivateMFADevice(&iam.DeactivateMFADeviceInput{
					UserName:     &user.Name,
					SerialNumber: &user.MFA[0],
				})
				if err != nil {
					log.Errorf("User: %s MSG: %s", user.Name, err)
				} else {
					log.Debugf("Removing User %s MFA: %s API: %s", user.Name, user.MFA, result)
					log.Infof("Removing User: %s MFA: %s", user.Name, user.MFA)

				}

			} else {
				log.Debugf("Removing User:%s , MFA: %s (DRYRUN)", user.Name, user.MFA)
			}
		} else {
			user.MFA[0] = "None"
			log.Infof("User: %s MFA: %s", user.Name, user.MFA)
		}

	}

}

func policies(user *User) {

	result, err := svc.ListAttachedUserPolicies(&iam.ListAttachedUserPoliciesInput{
		UserName: &user.Name,
	})
	if err != nil {
		log.Errorf("User: %s MSG: %s", user.Name, err)
	} else {
		log.Debugf("User: %s Policies: %s API: %+v", user.Name, result.AttachedPolicies, result)
		user.Policies = make([]string, len(result.AttachedPolicies))
		for i, k := range result.AttachedPolicies {
			user.Policies[i] = *k.PolicyArn
			if !dryrun {
				result, err := svc.DetachUserPolicy(&iam.DetachUserPolicyInput{
					UserName:  &user.Name,
					PolicyArn: &user.Policies[i],
				})
				log.Debugf("User: %s API: %s", user.Name, result)
				if err != nil {
					log.Errorf("User: %s Policy: %s MSG: %s ", user.Name, user.Policies[i], err)
				} else {
					log.Infof("Detach User: %s Policy: %s", user.Name, user.Policies[i])
				}
			} else {
				log.Infof("Detach User: %s Policy: %s (DRYRUN)", user.Name, user.Policies[i])
			}
		}

		log.Debugf("User: %s Policies: %s", user.Name, user.Policies)

	}

}

func group(user *User) {
	log.Infof("Querying Groups Attached to User: %s", user.Name)
	result, err := svc.ListGroupsForUser(&iam.ListGroupsForUserInput{
		UserName: &user.Name,
	})
	if err != nil {
		log.Errorf("User: %s MSG: %s", user.Name, err)
	} else {
		log.Debugf("User: %s API: %s", user.Name, result)
		user.Groups = make([]string, len(result.Groups))
		for i, k := range result.Groups {
			user.Groups[i] = *k.GroupName
			if !dryrun {
				result, err := svc.RemoveUserFromGroup(&iam.RemoveUserFromGroupInput{
					UserName:  &user.Name,
					GroupName: &user.Groups[i],
				})
				if err != nil {
					log.Errorf("User: %s MSG: %s", user.Name, err)
				} else {
					log.Debugf("Use:%s API:%s", user.Name, result)
					log.Infof("Removing User:%s from Group: %s", user.Name, k)

				}
			}else{
				log.Infof("User: %s Removing from Group %s",user.Name,k)
		}
	}
}}

func removeUser(user *User) {

	log.Infof("Attempting to Remove User: %s",user.Name)
	result,err := svc.DeleteUser(&iam.DeleteUserInput{
		UserName:&user.Name,
	})
	log.Debugf("User:%s API: %s",user.Name,result)
	if err != nil{
		log.Debugf("User: %s MSG: %s",user.Name,err)
	}else{
		log.Infof("Removed User: %s",user.Name)
	}

}
