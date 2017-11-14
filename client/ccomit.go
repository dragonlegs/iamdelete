package client

import "github.com/aws/aws-sdk-go/service/iam"

func codecommit(user *User){

	codeCommitKeys(user)


}

func codeCommitKeys(user *User){

	log.Info("User: %s Checking Code Commit keys")
	result , err := svc.ListSSHPublicKeys(&iam.ListSSHPublicKeysInput{
		UserName: &user.Name,
	})
	log.Debugf("User: %s ListSSH Keys API: %s",user.Name,result)
	if err != nil{
		log.Errorf("User:%s Error: %s ",user.Name,result)
	}else{
		user.CodeCommitSSH = make([]string,len(result.SSHPublicKeys))
		for i,k := range result.SSHPublicKeys {
			user.CodeCommitSSH[i] = *k.SSHPublicKeyId
			log.Infof("User: %s SSH Keys CodeCommit: %s ", user.Name, *k.SSHPublicKeyId )
			if !dryrun{
				result ,err := svc.DeleteSSHPublicKey(&iam.DeleteSSHPublicKeyInput{
					UserName: &user.Name,
					SSHPublicKeyId: &user.CodeCommitSSH[i],
				})
				log.Debugf("User: %s Delete SSH Keys CodeCommit: %s API: %s",user.Name,user.CodeCommitSSH[i],result)
				if err != nil{
					log.Errorf("User:%s MSG: %s",user.Name,err)
				}else{
					log.Infof("User: %s Removed SSH: %s ",user.Name,user.CodeCommitSSH[i])
				}
			}else{
				log.Infof("user: %s Removed SSH: %s (Removed)",user.Name,user.CodeCommitSSH[i])
			}
		}
	}

}
