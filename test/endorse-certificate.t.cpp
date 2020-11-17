/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

#if __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#pragma clang diagnostic ignored "-Wunused-function"
#elif __GNUC__
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

#include <boost/test/unit_test.hpp>
#include <boost/filesystem.hpp>

#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/util/time.hpp>
#include <ndn-cxx/util/io.hpp>
#include "cryptopp.hpp"
#include "endorse-certificate.hpp"

namespace chronochat {
namespace tests {

using std::vector;
using std::string;

using ndn::KeyChain;
using ndn::security::v2::Certificate;

BOOST_AUTO_TEST_SUITE(TestEndorseCertificate)

const string testIdCert("\
Bv0Czwc5CBdFbmRvcnNlQ2VydGlmaWNhdGVUZXN0cwgDS0VZCAg2x+MG7IxCPQgE\
c2VsZggJ/QAAAXXVNWGzFAkYAQIZBAA27oAV/QEmMIIBIjANBgkqhkiG9w0BAQEF\
AAOCAQ8AMIIBCgKCAQEAv3BM/bpWTmcKTeOzykiFm/GWYnhJgTQxQlRp4mQHsEmH\
SFmrCtx2g0mwoPUPwjBhXuH0J4PSIuudb8VLiPGD03/gFUeGtY9VRrH5dZuIOpHT\
tklBz8rA3DsCf0rMggU6IrYd6Vjlk+hseoAlKvVVgmGT+NXdmtO+Xhxt16S2jPUs\
+ZxKc+gBGKEHKKZkEDlRWzWrj+hBKasOic3v7Lc22M4tvjANxyMApZ/rXKdIi1rN\
Da0u4dk6lL/qW5fIEQEjsf4dngZkHaHkpK6wEnXyTQIX71/cmMB42xggfZ7YAvfO\
smuc0mg3fuuwTMo5fKxHCES14i6y7TMhqlxkgdb66QIDAQABFlkbAQEcKgcoCBdF\
bmRvcnNlQ2VydGlmaWNhdGVUZXN0cwgDS0VZCAg2x+MG7IxCPf0A/Sb9AP4PMTk3\
MDAxMDFUMDAwMDAw/QD/DzIwNDAxMTEyVDA3NTcyNhf9AQA0C8yYGgrruSJe1n5q\
oTSdmomnRdZgdczblgL5jY9dP9OAUJL6vy5bHwnjFU484T6vKANETL/BZfnkI/h9\
39gMjXiqaQ4zStuSNBVO/41IyOzDbg2KyQk41mB1M1r7pvzIziNM//ammYBzaQN/\
ixlKPrReUIypEswYnCXaw4VZPLkReR8yjVqLW2B6X8a1zfDWMOyv39Gayhpfcvbo\
2juJZ75JTk6KL8lEO8KO84M2ym/VABDZUHbXnMPYmqU4aMRRLfytzeZlLOdRzLpb\
FrE4AHwudakhruPB39NluYu2IHhyIB0x1u4xxyzGfgoIRIPXnW4zoulFn9RFgg9A\
6lNM\
");

const string testKey("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv3BM/bpWTmcKTeOzykiF\
m/GWYnhJgTQxQlRp4mQHsEmHSFmrCtx2g0mwoPUPwjBhXuH0J4PSIuudb8VLiPGD\
03/gFUeGtY9VRrH5dZuIOpHTtklBz8rA3DsCf0rMggU6IrYd6Vjlk+hseoAlKvVV\
gmGT+NXdmtO+Xhxt16S2jPUs+ZxKc+gBGKEHKKZkEDlRWzWrj+hBKasOic3v7Lc2\
2M4tvjANxyMApZ/rXKdIi1rNDa0u4dk6lL/qW5fIEQEjsf4dngZkHaHkpK6wEnXy\
TQIX71/cmMB42xggfZ7YAvfOsmuc0mg3fuuwTMo5fKxHCES14i6y7TMhqlxkgdb6\
6QIDAQAB");

const string testEndorseCert("\
Bv0CYweICBdFbmRvcnNlQ2VydGlmaWNhdGVUZXN0cwgMRW5jb2RlRGVjb2RlCBFr\
c2stMTM5NDA3MjE0NzMzNQgMUFJPRklMRS1DRVJUCDMHMQgXRW5kb3JzZUNlcnRp\
ZmljYXRlVGVzdHMIBlNpbmdlcggOa3NrLTEyMzQ1Njc4OTAICf0AAAFMoXR8NRQD\
GAECFf0BqTCCAaUwIhgPMjAxMzEyMjYyMzIyNTRaGA8yMDEzMTIyNjIzMjI1NFow\
QDA+BgNVBCkTNy9FbmRvcnNlQ2VydGlmaWNhdGVUZXN0cy9FbmNvZGVEZWNvZGUv\
a3NrLTEzOTQwNzIxNDczMzUwgZ0wDQYJKoZIhvcNAQEBBQADgYsAMIGHAoGBAJ4G\
PkeFsjQ3qoVHrAMkg7WcqAU6JB7riQG76ZuywyKsaOPwbALOaKbE0KcGkJyqGwgd\
i0OaM2dEbSGjG4ial15ZxBUL2Sy9UQdhgq3BuNe/m899JMJj85cX6/5iJbpbTYrC\
er1Dio+48vHFajDTUIzImt/v7TXnemLqdny7CCbHAgERMIGcMGsGBysGAQUgAgEB\
Af8EXYhbiTGKCElERU5USVRZiyUvRW5kb3JzZUNlcnRpZmljYXRlVGVzdHMvRW5j\
b2RlRGVjb2RliRaKCGhvbWVwYWdliwpNeUhvbWVQYWdliQ6KBG5hbWWLBk15TmFt\
ZTAtBgcrBgEFIAICAQH/BB+MHYsLaW5zdGl0dXRpb26LBWdyb3VwiwdhZHZpc29y\
FgMbAQAXIHalD2NUzM7abX6QY+2qWNLVMC+ch2xnVyrlf89ZH/IV");

BOOST_AUTO_TEST_CASE(IdCert)
{
  boost::iostreams::stream<boost::iostreams::array_source> is(testIdCert.c_str(),
                                                              testIdCert.size());
  std::shared_ptr<Certificate> idCert = ndn::io::load<Certificate>(is);

  BOOST_CHECK(static_cast<bool>(idCert));

  BOOST_CHECK_EQUAL(idCert->getName().toUri(),
    "/EndorseCertificateTests/KEY/6%C7%E3%06%EC%8CB%3D/self/%FD%00%00%01u%D55a%B3");
}

BOOST_AUTO_TEST_CASE(ConstructFromIdCert)
{
  boost::iostreams::stream<boost::iostreams::array_source> is(testIdCert.c_str(),
                                                              testIdCert.size());
  std::shared_ptr<Certificate> idCert = ndn::io::load<Certificate>(is);

  Profile profile(*idCert);
  vector<string> endorseList;
  endorseList.push_back("email");
  endorseList.push_back("homepage");
  EndorseCertificate endorseCertificate(*idCert, profile, endorseList);

  boost::filesystem::path keyChainTmpPath =
    boost::filesystem::path(TEST_CERT_PATH) / "TestEndorseCertificate";
  KeyChain keyChain(std::string("sqlite3:").append(keyChainTmpPath.string()),
                    std::string("tpm-file:").append(keyChainTmpPath.string()));

  auto signOpts = ndn::security::SigningInfo(ndn::security::SigningInfo::SignerType::SIGNER_TYPE_SHA256);
  keyChain.sign(endorseCertificate, signOpts);
  const Block& endorseDataBlock = endorseCertificate.wireEncode();

  Data decodedEndorseData;
  decodedEndorseData.wireDecode(endorseDataBlock);
  EndorseCertificate decodedEndorse(decodedEndorseData);
  BOOST_CHECK_EQUAL(decodedEndorse.getProfile().get("IDENTITY"),
                    "/EndorseCertificateTests/EncodeDecode");
  BOOST_CHECK_EQUAL(decodedEndorse.getProfile().get("name"), "MyName");
  BOOST_CHECK_EQUAL(decodedEndorse.getProfile().get("homepage"), "MyHomePage");
  BOOST_CHECK_EQUAL(decodedEndorse.getEndorseList().size(), 2);
  BOOST_CHECK_EQUAL(decodedEndorse.getEndorseList().at(0), "email");
  BOOST_CHECK_EQUAL(decodedEndorse.getEndorseList().at(1), "homepage");
  BOOST_CHECK_EQUAL(decodedEndorse.getSigner(),
                    "/EndorseCertificateTests/EncodeDecode/ksk-1394072147335");
  BOOST_CHECK_EQUAL(decodedEndorse.getPublicKeyName(),
                    "/EndorseCertificateTests/EncodeDecode/ksk-1394072147335");
}

BOOST_AUTO_TEST_CASE(ConstructFromEndorseCert)
{
  boost::iostreams::stream<boost::iostreams::array_source> is(testEndorseCert.c_str(),
                                                              testEndorseCert.size());
  shared_ptr<Data> rawData = ndn::io::load<Data>(is);

  EndorseCertificate rawEndorse(*rawData);
  vector<string> endorseList;
  endorseList.push_back("institution");
  endorseList.push_back("group");
  endorseList.push_back("advisor");
  Name signer("/EndorseCertificateTests/Singer/ksk-1234567890");
  EndorseCertificate endorseCertificate(rawEndorse, signer, endorseList);

  boost::filesystem::path keyChainTmpPath =
    boost::filesystem::path(TEST_CERT_PATH) / "TestEndorseCertificate";
  KeyChain keyChain(std::string("sqlite3:").append(keyChainTmpPath.string()),
                    std::string("tpm-file:").append(keyChainTmpPath.string()));

  auto signOpts = ndn::security::SigningInfo(ndn::security::SigningInfo::SignerType::SIGNER_TYPE_SHA256);
  keyChain.sign(endorseCertificate, signOpts);

  const Block& endorseDataBlock = endorseCertificate.wireEncode();

  Data decodedEndorseData;
  decodedEndorseData.wireDecode(endorseDataBlock);
  EndorseCertificate decodedEndorse(decodedEndorseData);
  BOOST_CHECK_EQUAL(decodedEndorse.getProfile().get("IDENTITY"),
                    "/EndorseCertificateTests/EncodeDecode");
  BOOST_CHECK_EQUAL(decodedEndorse.getProfile().get("name"), "MyName");
  BOOST_CHECK_EQUAL(decodedEndorse.getProfile().get("homepage"), "MyHomePage");
  BOOST_CHECK_EQUAL(decodedEndorse.getEndorseList().size(), 3);
  BOOST_CHECK_EQUAL(decodedEndorse.getEndorseList().at(0), "institution");
  BOOST_CHECK_EQUAL(decodedEndorse.getEndorseList().at(1), "group");
  BOOST_CHECK_EQUAL(decodedEndorse.getEndorseList().at(2), "advisor");
  BOOST_CHECK_EQUAL(decodedEndorse.getSigner(),
                    "/EndorseCertificateTests/Singer/ksk-1234567890");
  BOOST_CHECK_EQUAL(decodedEndorse.getPublicKeyName(),
                    "/EndorseCertificateTests/EncodeDecode/ksk-1394072147335");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace chronochat
