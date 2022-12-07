package com.ihm.auth.config

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.PropertySource
import org.springframework.stereotype.Component

@Component
@Configuration
@PropertySource("classpath:application.properties")
class JwtProperties {
    @Value("\${jwt.secret}")
    val secret: String = ""
}