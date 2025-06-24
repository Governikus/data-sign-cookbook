package de.governikus.datasign.cookbook.util;

import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.pades.signature.PAdESExtensionService;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;

import java.util.List;
import java.util.Objects;


/**
 * For low level signature operations we use the European Union's
 * <a href="https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/Digital+Signature+Service+-++DSS">Digital Signature Service library</a>
 */
public class DSSFactory {

    public static PAdESService pAdESService() {
        return new PAdESService(offlineCertificateVerifier());
    }

    public static PAdESService pAdESService(byte[] timestamp) throws Exception {
        var pAdESService = pAdESService();
        pAdESService.setTspSource(new OnlyOnceTspSource(new TimeStampToken(new CMSSignedData(timestamp))));
        return pAdESService;
    }

    public static PAdESExtensionService pAdESExtensionService() {
        return new PAdESExtensionService(certificateVerifierForLtv());
    }

    public static CAdESService cAdESService() {
        return new CAdESService(certificateVerifierForLtv());
    }

    public static SignedDocumentValidator signedDocumentValidator(DSSDocument unsignedDocument, DSSDocument signedDocument) {
        var validator = SignedDocumentValidator.fromDocument(signedDocument);
        validator.setDetachedContents(List.of(unsignedDocument));
        validator.setCertificateVerifier(offlineCertificateVerifier());
        return validator;
    }

    private static CertificateVerifier offlineCertificateVerifier() {
        var verifier = new CommonCertificateVerifier();
        verifier.setAIASource(null);
        return verifier;
    }

    private static CertificateVerifier certificateVerifierForLtv() {
        var verifier = new CommonCertificateVerifier();
        verifier.setCheckRevocationForUntrustedChains(true);
        verifier.setOcspSource(new OnlineOCSPSource());
        verifier.setAIASource(new DefaultAIASource());
        return verifier;
    }

    /**
     * This {@link TSPSource} provides an already existing timestamp, once.
     */
    public static class OnlyOnceTspSource implements TSPSource {

        private final transient TimestampBinary timestampBinary;

        public OnlyOnceTspSource(TimeStampToken timeStampToken) {
            Objects.requireNonNull(timeStampToken);
            timestampBinary = new TimestampBinary(DSSASN1Utils.getDEREncoded(timeStampToken));
        }

        @Override
        public TimestampBinary getTimeStampResponse(DigestAlgorithm digestAlgorithm, byte[] digest) throws DSSException {
            return timestampBinary;
        }
    }
}
