/**
 * Copyright IBM Corporation 2016
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

import Kitura
import KituraNet
import LoggerAPI
import Credentials

import SwiftyJSON

import STwitter

import Foundation

// MARK CredentialsTwitterToken

/// Authentication using Facebook web login with OAuth.
/// See [Facebook's manual](https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow)
/// for more information.
public class CredentialsTwitter: CredentialsPluginProtocol {
    
    private var consumerKey: String
    
    private var consumerSecret: String
    
    private var requestTokenSecrets: [String:String] = [:]
    
    /// The URL that Facebook redirects back to.
    public var callbackUrl: String
    
    /// The name of the plugin.
    public var name: String {
        return "Twitter"
    }
    
    /// An indication as to whether the plugin is redirecting or not.
    public var redirecting: Bool {
        return true
    }
    
    /// User profile cache.
    public var usersCache: NSCache<NSString, BaseCacheElement>?
    
    /// A delegate for `UserProfile` manipulation.
    public var userProfileDelegate: UserProfileDelegate? {
        return nil
    }

    /// Initialize a `CredentialsFacebook` instance.
    ///
    /// - Parameter clientId: The App ID of the app in the Facebook Developer dashboard.
    /// - Parameter clientSecret: The App Secret of the app in the Facebook Developer dashboard.
    /// - Parameter callbackUrl: The URL that Facebook redirects back to.
    /// - Parameter options: A dictionary of plugin specific options.
    public init(consumerKey: String, consumerSecret: String, callbackUrl: String, options: [String:Any]?=nil) {
        self.consumerKey = consumerKey
        self.consumerSecret = consumerSecret
        self.callbackUrl = callbackUrl
    }
    
    /// Authenticate incoming request using Facebook web login with OAuth.
    ///
    /// - Parameter request: The `RouterRequest` object used to get information
    ///                     about the request.
    /// - Parameter response: The `RouterResponse` object used to respond to the
    ///                       request.
    /// - Parameter options: The dictionary of plugin specific options.
    /// - Parameter onSuccess: The closure to invoke in the case of successful authentication.
    /// - Parameter onFailure: The closure to invoke in the case of an authentication failure.
    /// - Parameter onPass: The closure to invoke when the plugin doesn't recognize the
    ///                     authentication data in the request.
    /// - Parameter inProgress: The closure to invoke to cause a redirect to the login page in the
    ///                     case of redirecting authentication.
    public func authenticate(request: RouterRequest, response: RouterResponse,
                             options: [String:Any], onSuccess: @escaping (UserProfile) -> Void,
                             onFailure: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                             onPass: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                             inProgress: @escaping () -> Void) {
        if let requestToken = request.queryParameters["oauth_token"],
            let oauthVerifier = request.queryParameters["oauth_verifier"] {
            guard let requestTokenSecret = self.requestTokenSecrets[requestToken] else {
                onFailure(nil, nil)
                return
            }
            
            self.requestTokenSecrets[requestToken] = nil
            
            let twitterSession = STwitter.Session(consumerKey: self.consumerKey, consumerSecret: self.consumerSecret)
            
            STwitter.OAuth.requestAccessToken(session: twitterSession, requestToken: requestToken, requestTokenSecret: requestTokenSecret, oauthVerifier: oauthVerifier, completionHandler: { (accessToken, accessTokenSecret, userID, screenName, error) in
                if let error = error {
                    Log.error("Failed to get access token")
                    Log.error("\(error)")
                    return
                }
                
                guard let accessToken = accessToken else {
                    onFailure(nil, nil)
                    return
                }
                
                guard let accessTokenSecret = accessTokenSecret else {
                    onFailure(nil, nil)
                    return
                }
                
                twitterSession.account = STwitter.Account(accessToken: accessToken, accessTokenSecret: accessTokenSecret)
                
                do {
                    let task = try twitterSession.fetchUserTaskForCurrentAccount(completionHandler: { (user, error) in
                        if let error = error {
                            Log.error("Failed to get user object")
                            Log.error("\(error)")
                            return
                        }
                        
                        guard let user = user else {
                            onFailure(nil, nil)
                            return
                        }
                        
                        onSuccess(user.toUserProfile(for: self.name))
                    })
                    task.resume()
                }
                catch {
                    Log.error("Failed to get user object request")
                }
            })
        }
        else {
            // Log in
            let twitterSession = STwitter.Session(consumerKey: self.consumerKey, consumerSecret: self.consumerSecret)
            
            STwitter.OAuth.requestRequestToken(session: twitterSession, callback: callbackUrl, completionHandler: { (requestToken, requestTokenSecret, error) in
                if let error = error {
                    Log.error("Failed to get request token")
                    Log.error("\(error)")
                    return
                }

                requestTokenSecrets[requestToken] = requestTokenSecret
                
                do {
                    try response.redirect("https://api.twitter.com/oauth/authenticate?oauth_token=\(requestToken)")
                    inProgress()
                }
                catch {
                    Log.error("Failed to redirect to Twitter login page")
                }
            })
        }
    }
}
