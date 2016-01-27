package com.github.davidmoten.ppk.maven;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
    private String publicKeyFile;

    @Parameter(property = "inputFile")
    private File inputFile;

    @Parameter(property = "outputFile")
    private File outputFile;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        try (InputStream is = new BufferedInputStream(new FileInputStream(inputFile));
                OutputStream os = new BufferedOutputStream(new FileOutputStream(outputFile));) {
            PPK.publicKey(publicKeyFile).encrypt(is, os);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
