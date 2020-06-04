
# VpnScaleTestFramework

A software framework for performing scale testing on a VPN server. Permits  emulating thousands of VPN devices.

## Overview

The VPN Scale Test Framework consists of the following parts. The first is an .NET Http Controller that tracks the state of tests and clients devices. The second is a light weight agent that accepts commands from the HTTP controller.

## Usage

### Launch the Test Controller Container

```docker run -it --rm VpnScaleTestController:latest```

### Launch an instance of the Test Agent Container

```docker run -it --rm VpnScaleTestAgent:latest [base url of controller] [Root Certificate]```

Repeat accross one or more test VMs until there are enough clients.

### Generating a test plan

```VpnScaleTestGenerator [user pfx] [test_id] [minimum client count] <[test_plan] >[test_plan.json]```

### Starting a test

```curl -s @[test_plan.json] [base url of controller]/starttest?testid=<test id>```

### Monitoring a test

```watch curl -s [base url of controller]```

### Gather test results

```curl -s [base url of controller]/endtest?testid=<test id>```

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit <https://cla.opensource.microsoft.com.>

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
