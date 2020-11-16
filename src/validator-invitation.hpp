/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef CHRONOCHAT_VALIDATOR_INVITATION_HPP
#define CHRONOCHAT_VALIDATOR_INVITATION_HPP

#include "common.hpp"

#include <ndn-cxx/security/validator.hpp>
#include <ndn-cxx/security/certificate-cache.hpp>

namespace chronochat {

class ValidatorInvitation
{
  typedef function<void(const std::string&)> OnValidationFailed;
  typedef function<void()> OnValidated;

public:
  class Error : public ndn::security::v2::ValidationError
  {
  public:
    Error(const std::string& what)
      : ndn::security::v2::ValidationError(0, what)
    {
    }
  };

  static const shared_ptr<ndn::security::v2::CertificateCache> DefaultCertificateCache;

  ValidatorInvitation();

  virtual
  ~ValidatorInvitation()
  {
  }

  void
  addTrustAnchor(const Name& keyName, const ndn::Buffer& key);

  void
  removeTrustAnchor(const Name& keyName);

  void
  cleanTrustAnchor();

protected:
  void
  checkPolicy(const Data& data,
              int stepCount,
              const OnDataValidated& onValidated);

  void
  checkPolicy(const Interest& interest,
              int stepCount,
              const OnInterestValidated& onValidated);

private:
  void
  internalCheck(const uint8_t* buf, size_t size,
                const Signature& sig,
                const Name& keyLocatorName,
                const Data& innerData,
                const OnValidated& onValidated,
                const OnValidationFailed& onValidationFailed);

private:
  typedef std::map<Name, ndn::Buffer> TrustAnchors;

  TrustAnchors m_trustAnchors;
};

} // namespace chronochat

#endif // CHRONOCHAT_VALIDATOR_INVITATION_HPP
