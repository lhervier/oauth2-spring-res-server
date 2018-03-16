package com.github.lhervier.oauth.resource.sample;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

@Configuration
@EnableResourceServer
public class Oauth2ResourceConfig extends ResourceServerConfigurerAdapter {

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.cors();
		http.authorizeRequests()
				.antMatchers("/api/**").authenticated()
				.anyRequest().permitAll();
	}

	@Bean
	public AccessTokenConverter accessTokenConverter() {
		return new DefaultAccessTokenConverter();
	}
	
	@Bean
	public ResourceServerTokenServices remoteTokenServices(
			@Value("${oauth2.resource.checkToken.url}") String checkTokenUrl,
			@Value("${oauth2.resource.checkToken.param:token}") String checkTokenParam,
			@Value("${oauth2.resource.clientId:}") String clientId,
			@Value("${oauth2.resource.secret:}") String secret) {
		final IntrospectionEndpointTokenService remoteTokenServices = new IntrospectionEndpointTokenService();
		remoteTokenServices.setCheckTokenEndpointUrl(checkTokenUrl);
		remoteTokenServices.setTokenName(checkTokenParam);
		remoteTokenServices.setClientId(clientId);
		remoteTokenServices.setClientSecret(secret);
		remoteTokenServices.setAccessTokenConverter(accessTokenConverter());
		return remoteTokenServices;
	}
}
