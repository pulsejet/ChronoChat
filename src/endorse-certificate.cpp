/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 *         Qiuhan Ding <qiuhanding@cs.ucla.edu>
 */

#include "endorse-certificate.hpp"
#include <boost/iostreams/stream.hpp>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/security/additional-description.hpp>
#include <ndn-cxx/security/validity-period.hpp>
#include "endorse-extension.hpp"
#include <list>

namespace chronochat {

using std::vector;
using std::string;

using ndn::security::v2::Certificate;
using ndn::OBufferStream;

const vector<string> EndorseCertificate::DEFAULT_ENDORSE_LIST;

EndorseExtension&
operator<<(EndorseExtension& endorseExtension, const vector<string>& endorseList)
{
  for (const auto& entry : endorseList)
    endorseExtension.addEntry(entry);

  return endorseExtension;
}

EndorseExtension&
operator>>(EndorseExtension& endorseExtension, vector<string>& endorseList)
{
  const std::list<string>& endorseEntries = endorseExtension.getEntries();
  for (const auto& entry: endorseEntries)
    endorseList.push_back(entry);

  return endorseExtension;
}

EndorseCertificate::EndorseCertificate(const Certificate& kskCertificate,
                                       const Profile& profile,
                                       const vector<string>& endorseList)
  : Certificate()
  , m_profile(profile)
  , m_endorseList(endorseList)
{
  m_keyName = kskCertificate.getName().getSubName(-1);
  m_signer = "SELF";

  Name dataName = m_keyName;
  dataName.append("PROFILE-CERT")
          .append("KEY")
          .append(m_keyName)
          .append(m_signer)
          .appendVersion();
  setName(dataName);

  setMetaInfo(kskCertificate.getMetaInfo());
  setContent(kskCertificate.getPublicKey().data(), kskCertificate.getPublicKey().size());

  ndn::security::v2::AdditionalDescription description;
  description.set("2.5.4.41", m_keyName.toUri());

  EndorseExtension endorseExtension;
  endorseExtension << m_endorseList;

  ndn::SignatureInfo signatureInfo;
  signatureInfo.addCustomTlv(description.wireEncode());
  signatureInfo.addCustomTlv(m_profile.wireEncode());
  signatureInfo.addCustomTlv(endorseExtension.wireEncode());

  try {
    signatureInfo.setValidityPeriod(kskCertificate.getValidityPeriod());
  } catch (tlv::Error&) {
    signatureInfo.setValidityPeriod(ndn::security::ValidityPeriod(
      time::system_clock::now(), time::system_clock::now() + time::days(3650)));
  }

  setSignatureInfo(signatureInfo);
}

EndorseCertificate::EndorseCertificate(const EndorseCertificate& endorseCertificate,
                                       const Name& signer,
                                       const vector<string>& endorseList)
  : Certificate()
  , m_keyName(endorseCertificate.m_keyName)
  , m_signer(signer)
  , m_profile(endorseCertificate.m_profile)
  , m_endorseList(endorseList)
{
  Name dataName = m_keyName;
  dataName.append("PROFILE-CERT")
        .append("KEY")
        .append(m_keyName)
        .append(m_signer)
        .appendVersion();
  setName(dataName);

  setMetaInfo(endorseCertificate.getMetaInfo());
  setContent(endorseCertificate.getPublicKey().data(), endorseCertificate.getPublicKey().size());

  ndn::security::v2::AdditionalDescription description;
  description.set("2.5.4.41", m_keyName.toUri());

  EndorseExtension endorseExtension;
  endorseExtension << m_endorseList;

  ndn::SignatureInfo signatureInfo;
  signatureInfo.addCustomTlv(description.wireEncode());
  signatureInfo.addCustomTlv(m_profile.wireEncode());
  signatureInfo.addCustomTlv(endorseExtension.wireEncode());

  try {
    signatureInfo.setValidityPeriod(endorseCertificate.getValidityPeriod());
  } catch (tlv::Error&) {
    signatureInfo.setValidityPeriod(ndn::security::ValidityPeriod(
      time::system_clock::now(), time::system_clock::now() + time::days(3650)));
  }

  setSignatureInfo(signatureInfo);
}

EndorseCertificate::EndorseCertificate(const Name& keyName,
                                       const ndn::Buffer& key,
                                       const time::system_clock::TimePoint& notBefore,
                                       const time::system_clock::TimePoint& notAfter,
                                       const Name& signer,
                                       const Profile& profile,
                                       const vector<string>& endorseList)
  : Certificate()
  , m_keyName(keyName)
  , m_signer(signer)
  , m_profile(profile)
  , m_endorseList(endorseList)
{
  Name dataName = m_keyName;
  dataName.append("PROFILE-CERT")
      .append("KEY")
      .append(m_keyName)
      .append(m_signer)
      .appendVersion();
  setName(dataName);

  setContent(key.data(), key.size());

  ndn::security::v2::AdditionalDescription description;
  description.set("2.5.4.41", m_keyName.toUri());

  EndorseExtension endorseExtension;
  endorseExtension << m_endorseList;

  ndn::SignatureInfo signatureInfo;
  signatureInfo.addCustomTlv(description.wireEncode());
  signatureInfo.addCustomTlv(m_profile.wireEncode());
  signatureInfo.addCustomTlv(endorseExtension.wireEncode());

  signatureInfo.setValidityPeriod(ndn::security::ValidityPeriod(notBefore, notAfter));

  setSignatureInfo(signatureInfo);
}

EndorseCertificate::EndorseCertificate(const EndorseCertificate& endorseCertificate)
  : Certificate(endorseCertificate)
  , m_keyName(endorseCertificate.m_keyName)
  , m_signer(endorseCertificate.m_signer)
  , m_profile(endorseCertificate.m_profile)
  , m_endorseList(endorseCertificate.m_endorseList)
{
}

EndorseCertificate::EndorseCertificate(const Data& data)
  : Certificate(data)
{
  const Name& dataName = data.getName();

  if(dataName.size() < 5 || dataName.get(-5).toUri() != "PROFILE-CERT")
    throw Error("No PROFILE-CERT component in data name!");

  m_keyName = dataName.getPrefix(-5);
  // m_signer.wireDecode(dataName.get(-2).blockFromValue());
  m_signer = "SELF";

  auto profileWire = getSignatureInfo().getCustomTlv(tlv::Profile);
  if (profileWire) {
    m_profile = Profile(*profileWire);
  }

  auto endorseExtensionBlock = getSignatureInfo().getCustomTlv(tlv::EndorseExtension);
  if (endorseExtensionBlock) {
    EndorseExtension endorseExtension(*endorseExtensionBlock);
    endorseExtension >> m_endorseList;
  }
}

} // namespace chronochat
