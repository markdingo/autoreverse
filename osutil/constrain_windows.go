package osutil

func Constrain(userName, groupName, chrootDir string) error {
	return nil
}

func ConstraintReport(chroot string) string {
	return "uid=windows gid=windows cwd=" + chroot
}
