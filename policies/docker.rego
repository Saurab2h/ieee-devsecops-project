package devsecops

deny contains msg if {
    not input[0].Config.User
    msg := "Container user not explicitly set"
}

deny contains msg if {
    not input[0].Config.ExposedPorts["8080/tcp"]
    msg := "Required application port not exposed"
}
