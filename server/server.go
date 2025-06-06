package server

import (
	"fmt"
	"na3/na3-auth/config"
)

func Init() {
	config := config.GetConfig()
	r := NewRouter()
	r.Run(config.GetString("server.port"))
	fmt.Println("Server started on port", config.GetString("server.port"))
}
