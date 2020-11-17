/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef CHRONOCHAT_VALIDATOR_PANEL_HPP
#define CHRONOCHAT_VALIDATOR_PANEL_HPP

#include "common.hpp"

#include <ndn-cxx/security/validator.hpp>
#include <ndn-cxx/security/certificate-cache.hpp>

namespace chronochat {

class ValidatorPanel
{
public:

  static const shared_ptr<ndn::security::v2::CertificateCache> DEFAULT_CERT_CACHE;

  ValidatorPanel(int stepLimit = 10,
                 const shared_ptr<ndn::security::v2::CertificateCache> cache = DEFAULT_CERT_CACHE);

  ~ValidatorPanel()
  {
  }

  void
  removeTrustAnchor(const Name& keyName);

protected:
  virtual void
  checkPolicy(const Data& data,
              int stepCount,
              const OnDataValidated& onValidated);

  virtual void
  checkPolicy(const Interest& interest,
              int stepCount)
  {
  }

private:
  // int m_stepLimit;
  shared_ptr<ndn::security::v2::CertificateCache> m_certificateCache;
  std::map<Name, ndn::Buffer> m_trustAnchors;
};

} // namespace chronochat

#endif // CHRONOCHAT_VALIDATOR_PANEL_HPP
