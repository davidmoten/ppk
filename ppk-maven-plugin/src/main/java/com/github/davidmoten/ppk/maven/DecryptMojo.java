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

@Mojo(name = "decrypt")
public final class DecryptMojo extends AbstractMojo {


    @Parameter(property = "privateKeyFile")
    private File privateKeyFile;

    @Parameter(property = "format", defaultValue="der")
    private String format = "der";
   

    @Parameter(property = "inputFile")
    private File inputFile;

    @Parameter(property = "outputFile")
    private File outputFile;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        getLog().info("inputFile exists " + inputFile.exists());
        outputFile.getParentFile().mkdirs();
        try (InputStream is = new BufferedInputStream(new FileInputStream(inputFile));
                OutputStream os = new BufferedOutputStream(new FileOutputStream(outputFile));) {
            if (Constants.DER.equalsIgnoreCase(format)) {
                PPK.privateKey(privateKeyFile).encrypt(is, os);
            } else if (Constants.BASE64.equalsIgnoreCase(format)) {
                PPK.privateKeyB64(privateKeyFile).encrypt(is, os);
            } else 
                throw new MojoExecutionException("format parameter not recognized: "+ format);
        } catch (IOException e) {
            throw new MojoExecutionException("decryption failed: " + e.getMessage(), e);
        }
    }

}
