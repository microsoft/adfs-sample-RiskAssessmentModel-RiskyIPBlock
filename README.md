
# Build Plug-ins with AD FS 2019 Risk Assessment Model

You can now build your own plug-ins to block or assign a risk score to authentication requests during various stages – request received, pre-authentication and post-authentication. This can be accomplished using the new Risk Assessment Model introduced with AD FS 2019. 

## What is the Risk Assessment Model?

The Risk Assessment Model is a set of interfaces and classes which enable developers to read authentication request headers and implement their own risk assessment logic. The implemented code (plug-in) then runs in line with AD FS authentication process. For eg, using the interfaces and classes included with the model, you can implement code to either block or allow authentication request based on the client IP address included in the request header. AD FS will execute the code for each authentication request and take appropriate action as per the implemented logic.

For more details please visit [AD FS Risk Assessment Model documentation](https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/development/ad-fs-risk-assessment-model)

## About this sample

This sample plug-in is meant to better understand how to build a risk assessment plug-in and run it in line with AD FS process. The code in this sample uses the new interfaces and classes introduced with the risk assessment model to block the requests coming from certain extranet IPs identified as risky. 

To learn how to build this sample plug-in please visit [Building a sample plug-in documentation](https://review.docs.microsoft.com/en-us/windows-server/identity/ad-fs/development/ad-fs-risk-assessment-model?branch=pr-en-us-27#building-a-sample-plug-in)

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
