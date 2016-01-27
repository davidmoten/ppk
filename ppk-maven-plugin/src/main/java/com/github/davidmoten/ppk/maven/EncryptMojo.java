package com.github.davidmoten.ppk.maven;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import com.github.davidmoten.security.PPK;

@Mojo(name = "encrypt")
public final class EncryptMojo extends AbstractMojo {

    @Parameter(property = "publicKeyFile")
    private File publicKeyFile;
    
    @Parameter(property = "format", defaultValue="der")
    private String format = "der";

    @Parameter(property = "inputFile")
    private File inputFile;

    @Parameter(property = "outputFile")
    private File outputFile;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        try (InputStream is = new BufferedInputStream(new FileInputStream(inputFile));
                OutputStream os = new BufferedOutputStream(new FileOutputStream(outputFile));) {
            PPK.publicKey(publicKeyFile).encrypt(is, os);
            if (Constants.DER.equalsIgnoreCase(format)) {
                PPK.publicKey(publicKeyFile).decrypt(is, os);
            } else if (Constants.BASE64.equalsIgnoreCase(format)) {
                PPK.privateKeyB64(publicKeyFile).decrypt(is, os);
            } else 
                throw new MojoExecutionException("format parameter not recognized: "+ format);
        } catch (IOException e) {
            throw new MojoExecutionException("encrypt failed: " + e.getMessage(), e);
        }
    }

}
