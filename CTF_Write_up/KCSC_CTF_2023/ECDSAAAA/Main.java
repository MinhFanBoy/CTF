import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {
        try {
            KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            System.out.println(publicKey);

            System.out.println("############################################# SIGN #############################################");
            Scanner sc = new Scanner(System.in);
            System.out.print("Enter msg: ");
            String msg = sc.nextLine();
            if (msg.equals("Hi im Gan Dam")) {
                System.out.println("Go to airport :<");
                System.exit(0);
            }
            String base64Ssignature = sign(msg, privateKey);
            System.out.printf("Signature: %s \n", base64Ssignature);

            System.out.println("############################################# VERIFY #############################################");
            System.out.print("Enter msg: ");
            String msgV = sc.nextLine();
            System.out.print("Enter signature: ");
            String signV = sc.nextLine();
            if (verify(msgV, signV, publicKey)) {
                if (msgV.equals("Hi im Gan Dam")) {
                    System.out.println("KCSC{_______________}");
                } else {
                    System.out.println("Go to airport :<");
                    System.exit(0);
                }
            } else {
                System.out.println("Go to airport :<");
                System.exit(0);
            }
        }
        catch (Exception e) {
            System.out.println(e);
        }
    }

    public static String sign(String msg, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA512withECDSAinP1363Format");
        signature.initSign(privateKey);
        signature.update(msg.getBytes("UTF-8"));
        String base64Ssignature = Base64.getEncoder().encodeToString(signature.sign());
        return base64Ssignature;
    }

    public static boolean verify(String msg, String base64Ssignature, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance("SHA512withECDSAinP1363Format");
        verifier.initVerify(publicKey);
        verifier.update(msg.getBytes("UTF-8"));
        byte[] signature = Base64.getDecoder().decode(base64Ssignature);
        return verifier.verify(signature);
    }
}