/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef CHRONOCHAT_VALIDATION_POLICY_INVITATION_HPP
#define CHRONOCHAT_VALIDATION_POLICY_INVITATION_HPP

#include "common.hpp"

#include <ndn-cxx/security/validation-policy.hpp>
#include <ndn-cxx/security/certificate-cache.hpp>

using ndn::security::v2::ValidationState;
using ndn::security::v2::ValidationPolicy;

namespace chronochat {

class ValidationPolicyInvitation : public ValidationPolicy
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

protected:
  void
  checkPolicy(const Data& data, const shared_ptr<ValidationState>& state,
              const ValidationPolicy::ValidationContinuation& continueValidation);

  void
  checkPolicy(const Interest& interest, const shared_ptr<ValidationState>& state,
              const ValidationPolicy::ValidationContinuation& continueValidation);

private:
  void
  internalCheck(const uint8_t* buf, size_t size,
                const Signature& sig,
                const Name& keyLocatorName,
                const Data& innerData,
                const OnValidated& onValidated,
                const OnValidationFailed& onValidationFailed);
};

} // namespace chronochat

#endif // CHRONOCHAT_VALIDATION_POLICY_INVITATION_HPP
