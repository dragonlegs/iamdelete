package client

import "github.com/aws/aws-sdk-go/service/iam"

func codecommit(user *User){

	codecommitkeys(user)
	gitcreds(user)


}

func codecommitkeys(user *User){

	//log.Info("User: %s Checking Code Commit keys",user.Name)
	result , err := svc.ListSSHPublicKeys(&iam.ListSSHPublicKeysInput{
		UserName: &user.Name,
	})
	log.Debugf("ListSSHPublicKeys User: %s ListSSH Keys API: %s",user.Name,result)
	if err != nil{
		log.Errorf("ListSSHPublicKeys User: %s MSG: %s ",user.Name,result)
	}else{
		user.CodeCommitSSH = make([]string,len(result.SSHPublicKeys))
		for i,k := range result.SSHPublicKeys {
			user.CodeCommitSSH[i] = *k.SSHPublicKeyId
			log.Infof("ListSSHPublicKeys User: %s SSHPublicKeys : %s ", user.Name, *k.SSHPublicKeyId )
			if !dryrun{
				results ,err := svc.DeleteSSHPublicKey(&iam.DeleteSSHPublicKeyInput{
					UserName: &user.Name,
					SSHPublicKeyId: &user.CodeCommitSSH[i],
				})
				log.Debugf("DeleteSSHPublicKey User: %s API: %s",user.Name,user.CodeCommitSSH[i],results)
				if err != nil{
					log.Errorf("DeleteSSHPublicKey User:%s MSG: %s",user.Name,err)
				}else{
					log.Infof("DeleteSSHPublicKey User: %s SSHPublicKeys: %s ",user.Name,user.CodeCommitSSH[i])
				}
			}else{
				log.Infof("(DRYRUN) DeleteSSHPublicKey User: %s SSH: %s (DRYRUN)",user.Name,user.CodeCommitSSH[i])
			}
		}
	}

}


func gitcreds(user *User){

	//log.Infof("User: %s Checking Git Creds for AWS CodeCommit", user.Name)
	result, err := svc.ListServiceSpecificCredentials(&iam.ListServiceSpecificCredentialsInput{
		UserName: &user.Name,
	})
	log.Debugf("ListServiceSpecificCredentials User:%s  API: %s ",user.Name,result)
	if err !=nil{
		log.Errorf("ListServiceSpecificCredentials User: %s MSG: %s",user.Name,err)
	}else{
		user.GitCreds = make([]string, len(result.ServiceSpecificCredentials))
		for i,k := range result.ServiceSpecificCredentials{
			user.GitCreds[i] = *k.ServiceUserName
			log.Infof("ListServiceSpecificCredentials User: %s CredsUserName: %s",user.Name,user.GitCreds[i])
			if !dryrun{
				results , err := svc.DeleteServiceSpecificCredential(&iam.DeleteServiceSpecificCredentialInput{
					UserName: &user.Name,
					ServiceSpecificCredentialId: k.ServiceSpecificCredentialId,

				})
				log.Debugf("DeleteServiceSpecificCredential User: %s API: %s",user.Name,results)
				if err != nil {
					log.Errorf("DeleteServiceSpecificCredential User:%s MSG: %s",user.Name,err)
				}else{
					log.Infof("DeleteServiceSpecificCredential User:%s CredsUserName: %s",user.Name,user.GitCreds[i])
				}
			}else{
				log.Infof("(DRYRUN) DeleteServiceSpecificCredential User:%s  CredsUserName: %s (DRYRUN)",user.Name,user.GitCreds[i])
			}
		}
	}

}
