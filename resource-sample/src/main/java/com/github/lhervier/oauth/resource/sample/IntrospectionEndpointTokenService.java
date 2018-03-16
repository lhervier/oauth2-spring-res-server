package com.github.lhervier.oauth.resource.sample;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import net.jodah.expiringmap.ExpirationPolicy;
import net.jodah.expiringmap.ExpiringMap;

/**
 * Queries the /check_token endpoint to obtain the contents of an access token.
 *
 * If the endpoint returns a 400 or 401 response, this indicates that the token is invalid.
 * 
 * If the endpoint returns property "username" or "user_id" property, they will be translated as "user_name".
 * Note that RFC7662 requires "username", but Spring Security looks for "user_name"...
 * 
 * If the endpoint returns no "client_id" property, its value will be extracted from the "aud" property (if present).
 * 
 * If the endpoint contains an "aud" property, it will be removed.
 * 
 * If no clientId/clientSecret are defined, the request to the endpoint won't send an Authorization header.
 * 
 * If the endpoint returns only an error_description, it will fail.
 *
 * @author Dave Syer
 * @author Luke Taylor
 *
 */
public class IntrospectionEndpointTokenService implements ResourceServerTokenServices {

	protected final Log logger = LogFactory.getLog(getClass());

	private RestOperations restTemplate;

	private String checkTokenEndpointUrl;

	private String clientId;

	private String clientSecret;

    private String tokenName = "token";

	private AccessTokenConverter tokenConverter = new DefaultAccessTokenConverter();

	private ExpiringMap<String, Map<String, Object>> cache = ExpiringMap.builder().variableExpiration().build();
	
	public IntrospectionEndpointTokenService() {
		restTemplate = new RestTemplate();
		((RestTemplate) restTemplate).setErrorHandler(new DefaultResponseErrorHandler() {
			@Override
			// Ignore 400 and 401 http errors
			public void handleError(ClientHttpResponse response) throws IOException {
				if (response.getRawStatusCode() != 400 && response.getRawStatusCode() != 401 ) {
					super.handleError(response);
				}
			}
		});
	}

	public void setRestTemplate(RestOperations restTemplate) {
		this.restTemplate = restTemplate;
	}

	public void setCheckTokenEndpointUrl(String checkTokenEndpointUrl) {
		this.checkTokenEndpointUrl = checkTokenEndpointUrl;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public void setAccessTokenConverter(AccessTokenConverter accessTokenConverter) {
		this.tokenConverter = accessTokenConverter;
	}

    public void setTokenName(String tokenName) {
        this.tokenName = tokenName;
    }

    @Override
	public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException, InvalidTokenException {

    	Map<String, Object> map = this.cache.get(accessToken);
    	if( map == null ) {
			MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
			formData.add(tokenName, accessToken);
			HttpHeaders headers = new HttpHeaders();
			if( !StringUtils.isEmpty(clientId) && !StringUtils.isEmpty(clientSecret) )
				headers.set("Authorization", getAuthorizationHeader(clientId, clientSecret));
			map = postForMap(checkTokenEndpointUrl, formData, headers);
			
			if (map.containsKey("error") || map.containsKey("error_description") ) {
				logger.debug("check_token returned error: " + map.get("error") + " / " + map.get("error_description"));
				throw new InvalidTokenException(accessToken);
			}

			// Get user_name from username
			if( !map.containsKey("user_name") && map.containsKey("username") ) {		// "username" if defined in RFC7662, but Spring needs "user_name"
				map.put("user_name", map.get("username"));
				map.remove("username");
			}
			
			// Get user_name from user_id
			if( !map.containsKey("user_name") && map.containsKey("user_id") ) {			// Google Cloud send "user_id" instead of" username"
				map.put("user_name", map.get("user_id"));
				map.remove("user_id");
			}
			
			// Get client_id from aud
			if( !map.containsKey("client_id") && map.containsKey("aud") ) {
				map.put("client_id", map.get("aud"));
			}
			
			// Remove aud
			map.remove("aud");				// If aud is present, Spring Security will check if it is equal to a single configured value (oauth2-resource by default).
			
			Assert.state(map.containsKey("client_id"), "Client id must be present in response from auth server");
			
			long expiresIn;
			if( map.containsKey("exp") ) {						// As defined in RFC7662
				long exp = Long.parseLong(map.get("exp").toString());
				expiresIn = exp - (System.currentTimeMillis() / 1000L);
			} else if(map.containsKey("expires_in") ) {			// Google Cloud sends a "expires_in" value
				expiresIn = (Long) map.get("expires_in");
			} else
				expiresIn = -1L;
			if( expiresIn > 0 )
				this.cache.put(accessToken, map, ExpirationPolicy.CREATED, expiresIn, TimeUnit.SECONDS);
    	}
    	
		return tokenConverter.extractAuthentication(map);
	}

	@Override
	public OAuth2AccessToken readAccessToken(String accessToken) {
		throw new UnsupportedOperationException("Not supported: read access token");
	}

	private String getAuthorizationHeader(String clientId, String clientSecret) {

		if(clientId == null || clientSecret == null) {
			logger.warn("Null Client ID or Client Secret detected. Endpoint that requires authentication will reject request with 401 error.");
		}

		String creds = String.format("%s:%s", clientId, clientSecret);
		try {
			return "Basic " + new String(Base64.encode(creds.getBytes("UTF-8")));
		}
		catch (UnsupportedEncodingException e) {
			throw new IllegalStateException("Could not convert String");
		}
	}

	private Map<String, Object> postForMap(String path, MultiValueMap<String, String> formData, HttpHeaders headers) {
		if (headers.getContentType() == null) {
			headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		}
		@SuppressWarnings("rawtypes")
		Map map = restTemplate.exchange(path, HttpMethod.POST,
				new HttpEntity<MultiValueMap<String, String>>(formData, headers), Map.class).getBody();
		@SuppressWarnings("unchecked")
		Map<String, Object> result = map;
		return result;
	}
}
