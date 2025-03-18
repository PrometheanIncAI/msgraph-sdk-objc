//
// Copyright (c) Microsoft Corporation. All Rights Reserved. Licensed under the MIT License. See License in the project root for license information.
//

#import "MSAuthenticationHandler.h"
#import "MSURLSessionTask.h"
#import "MSAuthenticationHandlerOptions.h"

@interface MSURLSessionTask()

- (void)setRequest:(NSMutableURLRequest *)request;

@end


@interface MSAuthenticationHandler()

@property (nonatomic, strong) id<MSGraphMiddleware> nextMiddleware;

@end

@implementation MSAuthenticationHandler

- (instancetype)initWithAuthenticationProvider:(id<MSAuthenticationProvider>)authProvider
{
    self = [super init];
    if(self)
    {
        _authenticationProvider = authProvider;
    }
    return self;
}

- (void)setAuthenticationProvider:(id<MSAuthenticationProvider>)authProvider
{
    _authenticationProvider = authProvider;
}

- (void)execute:(MSURLSessionTask *)task withCompletionHandler:(HTTPRequestCompletionHandler)completionHandler
{
    MSAuthenticationHandlerOptions *authHandlerOptions = [task getMiddlewareOptionWithType:MSMiddlewareOptionsTypeAuth];

    id<MSAuthenticationProvider> authProvider = authHandlerOptions.authenticationProvider?authHandlerOptions.authenticationProvider:_authenticationProvider;

    [authProvider getAccessTokenForProviderOptions:authHandlerOptions.authenticationProviderOptions andCompletion:^(NSString *accessToken, NSError *error) {
        if(!error)
        {
            NSMutableURLRequest *urlRequest = [task request];

            //INFO: ExplainEverything 2025
            //      If you include the Authorization header when issuing the PUT call,
            //      it may result in an HTTP 401 Unauthorized response.
            //      Only send the Authorization header and bearer token when issuing the POST during the first step.
            //      Don't include it when you issue the PUT call.
            //      https://learn.microsoft.com/en-us/graph/api/driveitem-createuploadsession?view=graph-rest-1.0#remarks
            if (![task.request.HTTPMethod isEqualToString:@"PUT"]) {
                [urlRequest setValue:[NSString stringWithFormat:@"Bearer %@",accessToken] forHTTPHeaderField:@"Authorization"];
            }

            [task setRequest:urlRequest];
            [self.nextMiddleware execute:task withCompletionHandler:^(id data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
                completionHandler(data, response, error);
            }];
        }
        else
        {
            completionHandler(nil, nil, error);
        }
    }];
}

- (void)setNext:(id<MSGraphMiddleware>)nextMiddleware
{
    if(_nextMiddleware)
    {
        [nextMiddleware setNext:_nextMiddleware];
    }
    _nextMiddleware = nextMiddleware;
}

@end
