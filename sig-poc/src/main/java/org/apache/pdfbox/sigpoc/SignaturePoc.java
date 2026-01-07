package org.apache.pdfbox.sigpoc;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import javax.imageio.ImageIO;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDPageContentStream.AppendMode;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts.FontName;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

/**
 * Proof of concept that produces a signed PDF, then appends an incremental update that is not
 * covered by the original ByteRange.
 */
public final class SignaturePoc
{
    private static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

    private SignaturePoc()
    {
    }

    public static void main(String[] args) throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        Path outputDir = Paths.get("target", "sig-poc");
        Files.createDirectories(outputDir);

        KeyMaterial keyMaterial = KeyMaterial.generate("CN=PDFBox Sig PoC");
        Path baseline = createBaseline(outputDir, keyMaterial);
        Path tampered = createTampered(baseline, outputDir);

        verifyAndReport("baseline.pdf", baseline);
        verifyAndReport("tampered.pdf", tampered);

        renderFirstPage(baseline, outputDir.resolve("baseline.png"));
        renderFirstPage(tampered, outputDir.resolve("tampered.png"));
    }

    private static Path createBaseline(Path outputDir, KeyMaterial keyMaterial)
            throws IOException, GeneralSecurityException
    {
        Path baseline = outputDir.resolve("baseline.pdf");
        ByteArrayOutputStream unsignedOut = new ByteArrayOutputStream();
        try (PDDocument unsignedDocument = new PDDocument())
        {
            PDPage page = new PDPage(PDRectangle.LETTER);
            unsignedDocument.addPage(page);
            drawCenteredText(unsignedDocument, page, "Original content");

            PDDocumentCatalog catalog = unsignedDocument.getDocumentCatalog();
            PDAcroForm acroForm = new PDAcroForm(unsignedDocument);
            acroForm.setSignaturesExist(true);
            acroForm.setAppendOnly(true);
            acroForm.setDefaultResources(new org.apache.pdfbox.pdmodel.PDResources());
            catalog.setAcroForm(acroForm);

            PDSignatureField signatureField = new PDSignatureField(acroForm);
            signatureField.setPartialName("Signature1");

            PDAnnotationWidget widget = signatureField.getWidgets().get(0);
            PDRectangle rect = new PDRectangle(50, 650, 200, 50);
            widget.setRectangle(rect);
            widget.setPage(page);
            page.getAnnotations().add(widget);
            acroForm.getFields().add(signatureField);

            unsignedDocument.save(unsignedOut);
        }

        try (PDDocument document = Loader.loadPDF(unsignedOut.toByteArray()))
        {
            PDAcroForm acroForm = document.getDocumentCatalog().getAcroForm();
            PDSignatureField signatureField = (PDSignatureField) acroForm.getField("Signature1");

            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setSignDate(new java.util.GregorianCalendar());
            signature.setName("PDFBox PoC");
            signatureField.setValue(signature);

            SignatureInterface signer = content -> sign(content, keyMaterial);
            document.addSignature(signature, signer);

            try (FileOutputStream output = new FileOutputStream(baseline.toFile()))
            {
                document.saveIncremental(output);
            }
        }

        return baseline;
    }

    private static Path createTampered(Path baseline, Path outputDir) throws IOException
    {
        Path tampered = outputDir.resolve("tampered.pdf");
        try (PDDocument document = Loader.loadPDF(baseline.toFile()))
        {
            PDPage page = document.getPage(0);
            try (PDPageContentStream contentStream = new PDPageContentStream(document, page,
                    AppendMode.APPEND, true, true))
            {
                contentStream.beginText();
                contentStream.setNonStrokingColor(Color.RED);
                contentStream.setFont(new PDType1Font(FontName.HELVETICA_BOLD), 72);
                contentStream.newLineAtOffset(100, 400);
                contentStream.showText("TAMPERED");
                contentStream.endText();
            }

            try (FileOutputStream output = new FileOutputStream(tampered.toFile()))
            {
                document.saveIncremental(output);
            }
        }

        return tampered;
    }

    private static void verifyAndReport(String label, Path path) throws Exception
    {
        System.out.println("=== " + label + " ===");
        byte[] fileBytes = Files.readAllBytes(path);
        try (PDDocument document = Loader.loadPDF(fileBytes))
        {
            PDSignature signature = document.getSignatureDictionaries().get(0);
            int[] byteRange = signature.getByteRange();
            System.out.println("ByteRange: " + Arrays.toString(byteRange));

            boolean cmsValid = verifyCmsSignature(signature, fileBytes);
            System.out.println("CMS signature verifies: " + cmsValid);

            long covered = (long) byteRange[0] + byteRange[1] + byteRange[2] + byteRange[3];
            boolean coversAll = covered == fileBytes.length;
            System.out.println("ByteRange covers entire file (minus Contents gap): " + coversAll);
        }
        System.out.println();
    }

    private static boolean verifyCmsSignature(PDSignature signature, byte[] fileBytes)
            throws IOException, CMSException, OperatorCreationException, CertificateException,
            CertificateEncodingException
    {
        byte[] contents = signature.getContents(new ByteArrayInputStream(fileBytes));
        byte[] signedContent = signature.getSignedContent(new ByteArrayInputStream(fileBytes));
        CMSProcessable signedData = new CMSProcessableByteArray(signedContent);
        CMSSignedData cmsSignedData = new CMSSignedData(signedData, contents);
        Store<X509CertificateHolder> certificates = cmsSignedData.getCertificates();
        SignerInformation signerInformation = cmsSignedData.getSignerInfos().getSigners()
                .iterator().next();
        Collection<X509CertificateHolder> matches = certificates.getMatches(
                signerInformation.getSID());
        X509CertificateHolder certificateHolder = matches.iterator().next();
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(
                certificateHolder);

        return signerInformation.verify(new JcaSimpleSignerInfoVerifierBuilder()
                .setProvider(PROVIDER)
                .build(certificate.getPublicKey()));
    }

    private static void renderFirstPage(Path pdf, Path destination) throws IOException
    {
        try (PDDocument document = Loader.loadPDF(pdf.toFile()))
        {
            PDFRenderer renderer = new PDFRenderer(document);
            BufferedImage image = renderer.renderImageWithDPI(0, 144);
            ImageIO.write(image, "PNG", destination.toFile());
        }
    }

    private static byte[] sign(InputStream content, KeyMaterial keyMaterial)
            throws IOException
    {
        List<X509Certificate> certChain = Collections.singletonList(keyMaterial.certificate);
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        try
        {
            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(PROVIDER)
                    .build(keyMaterial.privateKey);
            generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().setProvider(PROVIDER).build())
                            .build(contentSigner, keyMaterial.certificate));
            generator.addCertificates(new org.bouncycastle.cert.jcajce.JcaCertStore(certChain));
        }
        catch (OperatorCreationException | GeneralSecurityException | CMSException ex)
        {
            throw new IOException("Failed to set up signature generator", ex);
        }
        byte[] toSign = content.readAllBytes();
        CMSProcessableByteArray processable = new CMSProcessableByteArray(toSign);
        try
        {
            CMSSignedData signedData = generator.generate(processable, false);
            return signedData.getEncoded();
        }
        catch (CMSException ex)
        {
            throw new IOException("Failed to generate CMS signature", ex);
        }
    }

    private static void drawCenteredText(PDDocument document, PDPage page, String text)
            throws IOException
    {
        try (PDPageContentStream contentStream = new PDPageContentStream(document, page))
        {
            contentStream.beginText();
            contentStream.setFont(new PDType1Font(FontName.HELVETICA), 24);
            contentStream.newLineAtOffset(100, 700);
            contentStream.showText(text);
            contentStream.endText();
        }
    }

    private static final class KeyMaterial
    {
        private final PrivateKey privateKey;
        private final X509Certificate certificate;

        private KeyMaterial(PrivateKey privateKey, X509Certificate certificate)
        {
            this.privateKey = privateKey;
            this.certificate = certificate;
        }

        static KeyMaterial generate(String subject) throws GeneralSecurityException, IOException
        {
            try
            {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();

                Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000L);
                Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);

                X500Name issuer = new X500Name(subject);
                X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(issuer,
                        java.math.BigInteger.valueOf(System.currentTimeMillis()), notBefore, notAfter,
                        issuer, keyPair.getPublic());
                certificateBuilder.addExtension(Extension.basicConstraints, true,
                        new BasicConstraints(false));
                certificateBuilder.addExtension(Extension.keyUsage, true,
                        new org.bouncycastle.asn1.x509.KeyUsage(
                                org.bouncycastle.asn1.x509.KeyUsage.digitalSignature));

                ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider(PROVIDER)
                        .build(keyPair.getPrivate());
                X509CertificateHolder holder = certificateBuilder.build(signer);
                X509Certificate certificate = new JcaX509CertificateConverter()
                        .setProvider(PROVIDER)
                        .getCertificate(holder);
                certificate.checkValidity(new Date());
                certificate.verify(keyPair.getPublic());

                return new KeyMaterial(keyPair.getPrivate(), certificate);
            }
            catch (OperatorCreationException ex)
            {
                throw new GeneralSecurityException("Failed to create self-signed certificate", ex);
            }
        }
    }
}
