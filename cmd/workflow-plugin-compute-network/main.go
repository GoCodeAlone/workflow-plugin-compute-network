package main

import (
	"github.com/GoCodeAlone/workflow-plugin-compute-network/internal"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

var version = "0.0.0"

func main() {
	internal.Version = version
	sdk.Serve(internal.NewPlugin(),
		sdk.WithBuildVersion(sdk.ResolveBuildVersion(internal.Version)),
	)
}
