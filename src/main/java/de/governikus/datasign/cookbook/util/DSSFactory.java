package de.governikus.datasign.cookbook.util;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.pades.signature.ExternalCMSService;
import eu.europa.esig.dss.pades.signature.PAdESWithExternalCMSService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDefaultObjectFactory;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;

import java.util.Objects;


/**
 * For low level signature operations we use the European Union's
 * <a href="https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/Digital+Signature+Service+-++DSS">Digital Signature Service library</a>
 */
public class DSSFactory {

    public static ExternalCMSService externalCMSService() {
        return new ExternalCMSService(offlineCertificateVerifier());
    }

    public static ExternalCMSService externalCMSService(byte[] timestamp) throws Exception {
        var externalCMSService = externalCMSService();
        externalCMSService.setTspSource(new OnlyOnceTspSource(new TimeStampToken(new CMSSignedData(timestamp))));
        return externalCMSService;
    }

    public static PAdESWithExternalCMSService padesWithExternalCMSService() {
        var padesService = new PAdESWithExternalCMSService();
        padesService.setPdfObjFactory(new PdfBoxDefaultObjectFactory());
        padesService.setCertificateVerifier(offlineCertificateVerifier());
        return padesService;
    }

    private static CertificateVerifier offlineCertificateVerifier() {
        var verifier = new CommonCertificateVerifier();
        verifier.setAIASource(null);
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
