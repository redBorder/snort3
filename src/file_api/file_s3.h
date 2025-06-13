#include <string>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <cpr/cpr.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <cstdlib>
#include <thread>
#include <chrono>
#include <iostream>
#include <stdexcept>

class SimpleS3UploaderV4 {
public:
    SimpleS3UploaderV4(const std::string& bucket,
                       const std::string& region,
                       const std::string& host = "s3.amazonaws.com",
                       const std::string& scheme = "https",
                       bool verifySsl = true,
                       const std::string& accessKey = "",
                       const std::string& secretKey = "")
        : bucket_(bucket),
          region_(region),
          host_(host),
          scheme_(scheme),
          verifySsl_(verifySsl) 
    {
        accessKey_ = accessKey.empty() ? getenvOrThrow("AWS_ACCESS_KEY_ID") : accessKey;
        secretKey_ = secretKey.empty() ? getenvOrThrow("AWS_SECRET_ACCESS_KEY") : secretKey;
    }

    cpr::Response putObject(const std::string& objectKey, const std::string& body, const std::string& contentType = "text/plain") {
        std::string encodedKey = urlEncode(objectKey);

        std::string service = "s3";
        std::string amzDate = getISO8601Timestamp();
        std::string dateStamp = getDateStamp();

        std::string canonicalUri = "/" + bucket_ + "/" + encodedKey;

        std::string canonicalQueryString = "";
        std::string payloadHash = sha256Hex(body);

        std::string signedHeaders = "host;x-amz-content-sha256;x-amz-date";
        std::string canonicalHeaders = "host:" + host_ + "\n"
                                     + "x-amz-content-sha256:" + payloadHash + "\n"
                                     + "x-amz-date:" + amzDate + "\n";

        std::string canonicalRequest = "PUT\n" + canonicalUri + "\n" + canonicalQueryString + "\n" +
                                       canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash;

        std::string credentialScope = dateStamp + "/" + region_ + "/" + service + "/aws4_request";
        std::string stringToSign = "AWS4-HMAC-SHA256\n" + amzDate + "\n" + credentialScope + "\n" + sha256Hex(canonicalRequest);

        std::string signingKey = getSignatureKey(secretKey_, dateStamp, region_, service);
        std::string signature = hmacSha256Hex(signingKey, stringToSign);

        std::string authorizationHeader = "AWS4-HMAC-SHA256 Credential=" + accessKey_ + "/" + credentialScope +
                                          ", SignedHeaders=" + signedHeaders +
                                          ", Signature=" + signature;

        std::string fullUrl = scheme_ + "://" + host_ + canonicalUri;

        for (int attempt = 0; attempt < 2; ++attempt) {
            cpr::Response response = cpr::Put(
                cpr::Url{fullUrl},
                cpr::Body{body},
                cpr::Header{
                    {"Host", host_},
                    {"Authorization", authorizationHeader},
                    {"x-amz-content-sha256", payloadHash},
                    {"x-amz-date", amzDate},
                    {"Content-Type", contentType}
                },
                cpr::VerifySsl{verifySsl_}
            );

            if (response.status_code >= 200 && response.status_code < 300) {
                return response;
            }

            if (response.status_code == 500 || response.status_code == 503) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }

            return response;
        }
    }

private:
    std::string accessKey_;
    std::string secretKey_;
    std::string bucket_;
    std::string region_;
    std::string host_;
    std::string scheme_;
    bool verifySsl_;

    static std::string getenvOrThrow(const std::string& name) {
        const char* val = std::getenv(name.c_str());
        if (!val) val = "";
        return std::string(val);
    }

    static std::string getISO8601Timestamp() {
        std::time_t t = std::time(nullptr);
        std::tm* gmt = std::gmtime(&t);
        char buf[17];
        std::strftime(buf, sizeof(buf), "%Y%m%dT%H%M%SZ", gmt);
        return std::string(buf);
    }

    static std::string getDateStamp() {
        std::time_t t = std::time(nullptr);
        std::tm* gmt = std::gmtime(&t);
        char buf[9];
        std::strftime(buf, sizeof(buf), "%Y%m%d", gmt);
        return std::string(buf);
    }

    static std::string sha256Hex(const std::string& data) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), hash);
        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        return ss.str();
    }

    static std::string hmacSha256Hex(const std::string& key, const std::string& data) {
        unsigned char* result;
        unsigned int len = SHA256_DIGEST_LENGTH;
        result = HMAC(EVP_sha256(), key.data(), key.size(),
                      reinterpret_cast<const unsigned char*>(data.data()), data.size(), nullptr, nullptr);
        std::stringstream ss;
        for (unsigned int i = 0; i < len; ++i)
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)result[i];
        return ss.str();
    }

    static std::string hmacSha256Raw(const std::string& key, const std::string& data) {
        unsigned char result[SHA256_DIGEST_LENGTH];
        HMAC(EVP_sha256(), key.data(), key.size(),
             reinterpret_cast<const unsigned char*>(data.data()), data.size(), result, nullptr);
        return std::string(reinterpret_cast<char*>(result), SHA256_DIGEST_LENGTH);
    }

    static std::string getSignatureKey(const std::string& key, const std::string& dateStamp,
                                       const std::string& region, const std::string& service) {
        std::string kDate = hmacSha256Raw("AWS4" + key, dateStamp);
        std::string kRegion = hmacSha256Raw(kDate, region);
        std::string kService = hmacSha256Raw(kRegion, service);
        std::string kSigning = hmacSha256Raw(kService, "aws4_request");
        return kSigning;
    }

    static std::string urlEncode(const std::string& value) {
        std::ostringstream escaped;
        escaped.fill('0');
        escaped << std::hex << std::uppercase;
        for (char c : value) {
            if (isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == '~' || c == '/') {
                escaped << c;
            } else {
                escaped << '%' << std::setw(2) << int((unsigned char)c);
            }
        }
        return escaped.str();
    }
};