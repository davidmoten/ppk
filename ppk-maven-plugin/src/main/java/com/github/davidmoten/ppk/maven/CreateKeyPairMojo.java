package com.github.davidmoten.ppk.maven;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import com.github.davidmoten.security.KeyPair;
import com.github.davidmoten.security.PPK;

@Mojo(name = "create")
public final class CreateKeyPairMojo extends AbstractMojo {

    @Parameter(property = "privateKeyFile")
    private File privateKeyFile;

    @Parameter(property = "publicKeyFile")
    private File publicKeyFile;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        KeyPair kp = PPK.createKeyPair();
        try {
            privateKeyFile.getParentFile().mkdirs();
            Files.write(privateKeyFile.toPath(), kp.privateKeyDer());
        } catch (IOException e) {
            throw new MojoExecutionException("could not create private key", e);
        }
        try {
            publicKeyFile.getParentFile().mkdirs();
            Files.write(publicKeyFile.toPath(), kp.publicKeyDer());
        } catch (IOException e) {
            throw new MojoExecutionException("could not create public key: "+ e.getMessage(), e);
        }
    }

}
