#ifndef SIMPLE_S3_UPLOADER_V4_H
#define SIMPLE_S3_UPLOADER_V4_H

#include <string>
#include <cpr/cpr.h>

class SimpleS3UploaderV4 {
public:
    SimpleS3UploaderV4(const std::string& bucket,
                       const std::string& region,
                       const std::string& host = "s3.amazonaws.com",
                       const std::string& scheme = "https",
                       bool verifySsl = true,
                       const std::string& accessKey = "",
                       const std::string& secretKey = "");

    cpr::Response putObject(const std::string& objectKey, const std::string& body, const std::string& contentType = "text/plain");

private:
    std::string accessKey_;
    std::string secretKey_;
    std::string bucket_;
    std::string region_;
    std::string host_;
    std::string scheme_;
    bool verifySsl_;

    static std::string getenvOrThrow(const std::string& name);
    static std::string getISO8601Timestamp();
    static std::string getDateStamp();
    static std::string sha256Hex(const std::string& data);
    static std::string hmacSha256Hex(const std::string& key, const std::string& data);
    static std::string hmacSha256Raw(const std::string& key, const std::string& data);
    static std::string getSignatureKey(const std::string& key, const std::string& dateStamp,
                                       const std::string& region, const std::string& service);
    static std::string urlEncode(const std::string& value);
};

#endif // SIMPLE_S3_UPLOADER_V4_H
