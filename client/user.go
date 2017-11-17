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
	Policies []string
	InLinePolicies []string
	Groups   []string
	CodeCommitSSH	 []string
	GitCreds  []string
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
	inlinepolicies(username)
	if ccommit{
		codecommit(username)
	}
	if !dryrun{
		removeUser(username)
	}
}

func getUserInfo(user *User) bool{
	log.Debugf("Checking if %s exists",user.Name)
	results, err := svc.GetUser(&iam.GetUserInput{
		UserName: &user.Name,
	})
	log.Debugf("GetUser User: %s API: %s",user.Name,results)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == iam.ErrCodeNoSuchEntityException {
				log.Errorf("Unable to find User: %s",user.Name)
				log.Debugf("GetUser User: %s API:%s",user.Name,results)
				return false
			}
		}
		log.Errorf("GetUser User: %s MSG:%s",user.Name,err)
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
		log.Errorf("User: %s ListAccessKeys MSG: %s", user.Name, err)
	} else {
		log.Debugf("User %s: ListAccessKeys API: %s", user.Name, results)
		user.AccessID = make([]string, len(results.AccessKeyMetadata))
		for i, k := range results.AccessKeyMetadata {
			user.AccessID[i] = *k.AccessKeyId
			log.Infof("GetAccesskey User: %s AccessKeys: %s", user.Name, *k.AccessKeyId)
			if !dryrun {
				result, err := svc.DeleteAccessKey(&iam.DeleteAccessKeyInput{
					AccessKeyId: k.AccessKeyId,
					UserName:    &user.Name,
				})
				if err != nil {
					log.Errorf("DeleteAccessKey User: %s  MSG: %s", user.Name, err)
				} else {
					log.Infof("DeleteAccessKey User: %s AccessKeyId: %s",user.Name,user.AccessID[i])
					log.Debugf("DeleteAccessKey User: %s , AccessKeyId: %s API Result: %s", user.Name, *k.AccessKeyId, result)
				}

			} else {
				log.Infof("(DRYRUN) DeleteAccessKey User: %s AccessKeyId: %s (DRYRUN)",user.Name,user.AccessID[i])
			}

		}
	}
}

func certificate(user *User) {

	result, err := svc.ListSigningCertificates(&iam.ListSigningCertificatesInput{
		UserName: &user.Name,
	})
	if err != nil {
		log.Errorf("User: %s ListSigningCertificates MSG: %s", user.Name, err)
	} else {
		//log.Debugf("Querying Certificate User %s: Result: %s",user.Name,results)
		user.Certs = make([]string, len(result.Certificates))
		for i, k := range result.Certificates {
			user.Certs[i] = *k.CertificateId
			log.Infof("GetSigningCertificates User: %s Certificate: %s", user.Name, *k.CertificateId)
			if !dryrun {

				results, err := svc.DeleteSigningCertificate(&iam.DeleteSigningCertificateInput{
					CertificateId: k.CertificateId,
					UserName:      &user.Name,
				})
				if err != nil {
					log.Errorf("DeleteSigningCertificate User: %s MSG: %s", user.Name, err)
				} else {
					log.Debugf("DeleteSigningCertificate User:%s , Certificate: %s API Result: %s", user.Name, *k.CertificateId, results)
				}

			} else {
				log.Infof("(DRYRUN) DeleteSigningCertificate User:%s, Certificate: %s (DRYRUN)", user.Name, *k.CertificateId)
			}

		}
	}

}

func profile(user *User) {

	result, err := svc.GetLoginProfile(&iam.GetLoginProfileInput{
		UserName: &user.Name,
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == iam.ErrCodeNoSuchEntityException {
				user.Password = false
				log.Infof("GetLoginProfile User: %s ConsolePassword: %t", user.Name, user.Password)

			} else {
				log.Errorf("GetLoginProfile User: %s MSG: %s", user.Name, err)

			}
			return
		}

	}
	log.Debugf("GetLoginProfile User %s: API: %s", user.Name, result)
	log.Infof("GetLoginProfile User: %s ConsolePassword: %t", user.Name, user.Password)
	if !dryrun {
		results, err := svc.DeleteLoginProfile(&iam.DeleteLoginProfileInput{
			UserName: &user.Name,
		})
		if err != nil {
			log.Errorf("DeleteLoginProfile User: %s MSG: %s", user.Name, err)
		} else {
			log.Debugf("DeleteLoginProfile User:%s , ConsolePassword: %t API Result: %s", user.Name, user.Password, results)
		}
	} else {
		log.Infof("(DRYRUN) DeleteLoginProfile User:%s, ConsolePassword: %t (DRYRUN)", user.Name, user.Password)
	}

}

func mfa(user *User) {

	result, err := svc.ListMFADevices(&iam.ListMFADevicesInput{
		UserName: &user.Name,
	})
	if err != nil {
		log.Error("ListMFADevices User %s : MSG: %s", user.Name, err)
	} else {
		log.Debugf("ListMFADevices User %s: API: %s", user.Name, result)
		if result.MFADevices != nil {
			user.MFA[0] = *result.MFADevices[0].SerialNumber
			if !dryrun {
				results, err := svc.DeactivateMFADevice(&iam.DeactivateMFADeviceInput{
					UserName:     &user.Name,
					SerialNumber: &user.MFA[0],
				})
				if err != nil {
					log.Errorf("DeactivateMFADevice User: %s MSG: %s", user.Name, err)
				} else {
					log.Debugf("DeactivateMFADevice User %s MFA: %s API: %s", user.Name, user.MFA, results)
					log.Infof("DeactivateMFADevice User: %s MFA: %s", user.Name, user.MFA)

				}

			} else {
				log.Debugf("(DRYRUN) DeactivateMFADevice User:%s , MFA: %s (DRYRUN)", user.Name, user.MFA)
			}
		} else {
			user.MFA[0] = "None"
			log.Infof("MFADeviceNotFound User: %s MFA: %s", user.Name, user.MFA)
		}

	}

}

func policies(user *User) {

	result, err := svc.ListAttachedUserPolicies(&iam.ListAttachedUserPoliciesInput{
		UserName: &user.Name,
	})
	if err != nil {
		log.Errorf("ListAttachedUserPolicies User: %s MSG: %s", user.Name, err)
	} else {
		log.Debugf("ListAttachedUserPolicies User: %s API: %+v", user.Name, result.AttachedPolicies, result)
		user.Policies = make([]string, len(result.AttachedPolicies))
		for i, k := range result.AttachedPolicies {
			user.Policies[i] = *k.PolicyArn
			if !dryrun {
				results, err := svc.DetachUserPolicy(&iam.DetachUserPolicyInput{
					UserName:  &user.Name,
					PolicyArn: &user.Policies[i],
				})
				log.Debugf("DetachUserPolicy User: %s API: %s", user.Name, results)
				if err != nil {
					log.Errorf("DetachUserPolicy User: %s Policy: %s MSG: %s ", user.Name, user.Policies[i], err)
				} else {
					log.Infof("DetachUserPolicy User: %s Policy: %s", user.Name, user.Policies[i])
				}
			} else {
				log.Infof("(DRYRUN) DetachUserPolicy User: %s Policy: %s (DRYRUN)", user.Name, user.Policies[i])
			}
		}


	}

}

func inlinepolicies(user *User) {

	result, err := svc.ListUserPolicies(&iam.ListUserPoliciesInput{
		UserName: &user.Name,
	})
	if err != nil {
		log.Errorf("ListUserPolicies User: %s MSG: %s", user.Name, err)
	} else {
		log.Debugf("ListUserPolicies User: %s API: %+v", user.Name, result.PolicyNames, result)
		user.InLinePolicies = make([]string, len(result.PolicyNames))
		for i, k := range result.PolicyNames {
			user.InLinePolicies[i] = *k
			if !dryrun {
				results, err := svc.DeleteUserPolicy(&iam.DeleteUserPolicyInput{
					UserName:  &user.Name,
					PolicyName: &user.InLinePolicies[i],
				})
				log.Debugf("DeleteUserPolicy User: %s API: %s", user.Name, results)
				if err != nil {
					log.Errorf("DeleteUserPolicy User: %s Policy: %s MSG: %s ", user.Name, user.InLinePolicies[i], err)
				} else {
					log.Infof("DeleteUserPolicy Detach User: %s Policy: %s", user.Name, user.InLinePolicies[i])
				}
			} else {
				log.Infof("(DRYRUN) DeleteUserPolicy User: %s Policy: %s (DRYRUN)", user.Name, user.InLinePolicies[i])
			}
		}


	}

}

func group(user *User) {
	result, err := svc.ListGroupsForUser(&iam.ListGroupsForUserInput{
		UserName: &user.Name,
	})
	if err != nil {
		log.Errorf("ListGroupsForUser User: %s MSG: %s", user.Name, err)
	} else {
		log.Debugf("ListGroupsForUser User: %s API: %s", user.Name, result)
		user.Groups = make([]string, len(result.Groups))
		for i, k := range result.Groups {
			user.Groups[i] = *k.GroupName
			log.Infof("ListGroupsForUser User: %s Group: %s",user.Name,user.Groups[i])
			if !dryrun {
				results, err := svc.RemoveUserFromGroup(&iam.RemoveUserFromGroupInput{
					UserName:  &user.Name,
					GroupName: &user.Groups[i],
				})
				if err != nil {
					log.Errorf("RemoveUserFromGroup User: %s MSG: %s", user.Name, err)
				} else {
					log.Debugf("RemoveUserFromGroup Use:%s API:%s", user.Name, results)
					log.Infof("RemoveUserFromGroup User:%s Group: %s", user.Name, k.GroupName)

				}
			}else{
				log.Infof("(DRYRUN) RemoveUserFromGroup User: %s Removing from Group %s (DRYRUN)",user.Name,user.Groups[i])
		}
	}
}}

func removeUser(user *User) {

	//log.Infof("Attempting to Remove User: %s",user.Name)
	result,err := svc.DeleteUser(&iam.DeleteUserInput{
		UserName:&user.Name,
	})
	log.Debugf("DeleteUser User:%s API: %s",user.Name,result)
	if err != nil{
		log.Errorf("DeleteUser User: %s MSG: %s",user.Name,err)
	}else{
		log.Infof("DeleteUser User: %s ",user.Name)
	}

}
