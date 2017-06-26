package br.ufsc.ine5611;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class App {
    public static void main(String[] args) throws Exception {

        File file = new File(args[1]);

        ProcessBuilder pb = new ProcessBuilder()
                .command(args[0])
                .redirectInput(ProcessBuilder.Redirect.PIPE)
                .redirectOutput(ProcessBuilder.Redirect.PIPE);

        Process process = pb.start();

        Path pathTempFile = Files.createTempFile("prefix",".suffix");

        FileChannel fc = FileChannel.open(pathTempFile, StandardOpenOption.WRITE, StandardOpenOption.READ);

        long fileLength = file.length();
        int hashLength = 32;
        int payload = 4;

        long size = fileLength + hashLength + payload;

        MappedByteBuffer mbb = fc.map(FileChannel.MapMode.READ_WRITE,0,size);

        fc.close();

        mbb.position(0);
        mbb.putInt((int) fileLength);

        FileInputStream fi = new FileInputStream(file);

        for(int i = fi.read(); i != -1; i = fi.read()){
            mbb.put((byte) i);
        }

        fi.close();

        for(int i=0; i<hashLength; i++){
            mbb.put((byte)0);
        }

        SignerClient sg = new SignerClient(process.getOutputStream(), process.getInputStream());

        sg.sign(pathTempFile.toFile());

        process.waitFor();

        int begin = payload + (int) fileLength;
        mbb.position(begin);
        byte[] hash = new byte[hashLength];

        mbb.get(hash);

        byte[] expected = getExpectedSignature(file);

        System.out.println(Arrays.equals(hash,  expected));
        System.out.println(Base64.getEncoder().encodeToString(hash));
        System.out.println(Base64.getEncoder().encodeToString(expected));
    }

    private static byte[] getExpectedSignature(File file) throws IOException {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unexpected exception", e);
        }
        try (FileInputStream in = new FileInputStream(file)) {
            while (in.available() > 0)
                md.update((byte) in.read());
        }
        return md.digest();
    }
}
