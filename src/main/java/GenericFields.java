/*
 * Example written by Bruno Lowagie in answer to:
 * http://stackoverflow.com/questions/33247348/add-pdfpcell-to-paragraph
 */

import com.itextpdf.text.*;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.*;
import sun.security.mscapi.SunMSCAPI;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;


/**
 * @author Bruno Lowagie (iText Software)
 */

public class GenericFields {
    public static final String SRC = "results/events/generic_fields.pdf";
    public static final String DEST = "results/events/generic_fields_signed.pdf";
    public static final char[] PASSWORD = "mechi1305".toCharArray();


    public class FieldChunk extends PdfPageEventHelper {
        @Override
        public void onGenericTag(PdfWriter writer, Document document, Rectangle rect, String text) {
            TextField field = new TextField(writer, rect, text);
            try {
                writer.addAnnotation(field.getTextField());
            } catch (IOException ex) {
                throw new ExceptionConverter(ex);
            } catch (DocumentException ex) {
                throw new ExceptionConverter(ex);
            }
        }
    }

    public static void main(String[] args) throws IOException, DocumentException {
        File file = new File(SRC);
        file.getParentFile().mkdirs();
        new GenericFields().createPdf(SRC);

        SunMSCAPI provider = new SunMSCAPI();
        Security.addProvider(provider);

        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("Windows-MY", "SunMSCAPI");
            ks.load(null, PASSWORD);
            String alias = ks.aliases().nextElement();
            PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
            Certificate[] chain = ks.getCertificateChain(alias);
            sign(SRC, String.format(DEST, 1), chain, pk, DigestAlgorithms.SHA256,
                    provider.getName(), MakeSignature.CryptoStandard.CMS, "Test 1", "Ghent", "signHere", ks);
            sign(SRC, String.format(DEST, 2), chain, pk, DigestAlgorithms.SHA512,
                    provider.getName(), MakeSignature.CryptoStandard.CMS, "Test 2", "Ghent", "signHere", ks);
            sign(SRC, String.format(DEST, 3), chain, pk, DigestAlgorithms.SHA256,
                    provider.getName(), MakeSignature.CryptoStandard.CADES, "Test 3", "Ghent", "signHere", ks);
            //sign(SRC, String.format(DEST, 4), chain, pk, DigestAlgorithms.RIPEMD160,
               //     provider.getName(), MakeSignature.CryptoStandard.CADES, "Test 4", "Ghent", "signHere", ks);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        //KeyStore ks = KeyStore.getInstance("PKCS11");



    }

    public void createPdf(String dest) throws IOException, DocumentException {
        Document document = new Document();
        PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream(dest));
        writer.setPageEvent(new FieldChunk());
        document.open();

        Paragraph p = new Paragraph();
        p.add("The Effective Date is ");
        Chunk day = new Chunk("     ");
        day.setGenericTag("day");
        p.add(day);
        p.add(" day of ");
        Chunk month = new Chunk("     ");
        month.setGenericTag("month");
        p.add(month);
        p.add(", ");
        Chunk year = new Chunk("            ");
        year.setGenericTag("year");
        p.add(year);
        p.add(" that this will begin.");

        document.add(p);
        document.close();
    }

    public static void sign(String src, String dest, Certificate[] chain, PrivateKey pk,
                            String digestAlgorithm, String provider, MakeSignature.CryptoStandard subfilter,
                            String reason, String location, String fieldToSign, KeyStore ks)
            throws GeneralSecurityException, IOException, DocumentException {

        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');

        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setVisibleSignature(new Rectangle(36, 748, 144, 780), 1, "sig");

        //appearance.setImage(Image.getInstance(Params.imgPath));
        //appearance.setImageScale(-1);

        // Creating the signature
        ExternalDigest digest = new ProviderDigest(provider);

        ExternalSignature signature = new PrivateKeySignature(pk, digestAlgorithm, ks.getProvider().getName());

        MakeSignature.signDetached(appearance, digest, signature, chain, null, null, null, 0, subfilter);

    }
}
