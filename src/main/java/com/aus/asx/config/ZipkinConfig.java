package com.aus.asx.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import brave.sampler.Sampler;

@Configuration
public class ZipkinConfig {
    @Bean
    public Sampler alwaysSampler() {
        return Sampler.ALWAYS_SAMPLE;
    }
}