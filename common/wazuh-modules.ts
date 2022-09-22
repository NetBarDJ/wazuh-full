/*
 * Wazuh app - Simple description for each App tabs
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
import {i18n} from '@kbn/i18n';

export const WAZUH_MODULES = {
  general: {
    title:
      i18n.translate('mywazuh.overview.general.title', {
        defaultMessage: 'Security events',
      }),
    description:
      i18n.translate('mywazuh.overview.general.des', {
        defaultMessage: 'Browse through your security alerts, identifying issues and threats in your environment.',
      })
  },
  fim: {
    title:
      i18n.translate('mywazuh.overview.fim.title', {
        defaultMessage: 'Integrity monitoring',
      }),
    description:
      i18n.translate('mywazuh.overview.fim.des', {
        defaultMessage: 'Alerts related to file changes, including permissions, content, ownership and attributes.',
      })
  },
  pm: {
    title: i18n.translate('mywazuh.overview.pm.title', {
      defaultMessage: 'Policy monitoring',
    }),
    description:
      i18n.translate('mywazuh.overview.pm.des', {
        defaultMessage: 'Verify that your systems are configured according to your security policies baseline.',
      })
  },
  vuls: {
    title: i18n.translate('mywazuh.overview.vuls.title', {
      defaultMessage: 'Vulnerabilities',
    }),
    description:
      i18n.translate('mywazuh.overview.vuls.des', {
        defaultMessage: 'Discover what applications in your environment are affected by well-known vulnerabilities.',
      })
  },
  oscap: {
    title: i18n.translate('mywazuh.overview.oscap.title', {
      defaultMessage: 'OpenSCAP',
    }),
    description:
      i18n.translate('mywazuh.overview.oscap.des', {
        defaultMessage: 'Configuration assessment and automation of compliance monitoring using SCAP checks.',
      })
  },
  audit: {
    title: i18n.translate('mywazuh.overview.audit.title', {
      defaultMessage: 'System auditing',
    }),
    description:
      i18n.translate('mywazuh.overview.audit.des', {
        defaultMessage: 'Audit users behavior, monitoring command execution and alerting on access to critical files.',
      })
  },
  pci: {
    title: i18n.translate('mywazuh.overview.pci.title', {
      defaultMessage: 'PCI DSS',
    }),
    description:
      i18n.translate('mywazuh.overview.pci.des', {
        defaultMessage: 'Global security standard for entities that process, store or transmit payment cardholder data.',
      })
  },
  gdpr: {
    title: i18n.translate('mywazuh.overview.gdpr.title', {
      defaultMessage: 'GDPR',
    }),
    description:
      i18n.translate('mywazuh.overview.gdpr.des', {
        defaultMessage: 'General Data Protection Regulation (GDPR) sets guidelines for processing of personal data.',
      })
  },
  hipaa: {
    title: i18n.translate('mywazuh.overview.hipaa.title', {
      defaultMessage: 'HIPAA',
    }),
    description:
      i18n.translate('mywazuh.overview.hipaa.des', {
        defaultMessage: 'Health Insurance Portability and Accountability Act of 1996 (HIPAA) provides data privacy and security provisions for safeguarding medical information.',
      })
  },
  nist: {
    title: i18n.translate('mywazuh.overview.nist.title', {
      defaultMessage: 'NIST 800-53',
    }),
    description:
      i18n.translate('mywazuh.overview.nist.des', {
        defaultMessage: 'National Institute of Standards and Technology Special Publication 800-53 (NIST 800-53) sets guidelines for federal information systems.',
      })
  },
  tsc: {
    title: i18n.translate('mywazuh.overview.tsc.title', {
      defaultMessage: 'TSC',
    }),
    description:
      i18n.translate('mywazuh.overview.tsc.des', {
        defaultMessage: 'Trust Services Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy',
      })
  },
  ciscat: {
    title: i18n.translate('mywazuh.overview.ciscat.title', {
      defaultMessage: 'CIS-CAT',
    }),
    description:
      i18n.translate('mywazuh.overview.ciscat.des', {
        defaultMessage: 'Configuration assessment using Center of Internet Security scanner and SCAP checks.',
      })
  },
  aws: {
    title: i18n.translate('mywazuh.overview.aws.title', {
      defaultMessage: 'Amazon AWS',
    }),
    description:
      i18n.translate('mywazuh.overview.aws.des', {
        defaultMessage: 'Security events related to your Amazon AWS services, collected directly via AWS API.',
      })
  },
  office: {
    title: i18n.translate('mywazuh.overview.office.title', {
      defaultMessage: 'Office 365',
    }),
    description:
      i18n.translate('mywazuh.overview.office.des', {
        defaultMessage: 'Security events related to your Office 365 services.',
      })
  },
  gcp: {
    title: i18n.translate('mywazuh.overview.gcp.title', {
      defaultMessage: 'Google Cloud Platform',
    }),
    description:
      i18n.translate('mywazuh.overview.gcp.des', {
        defaultMessage: 'Security events related to your Google Cloud Platform services, collected directly via GCP API.',
      }) // TODO GCP
  },
  virustotal: {
    title: i18n.translate('mywazuh.overview.virustotal.title', {
      defaultMessage: 'VirusTotal',
    }),
    description:
      i18n.translate('mywazuh.overview.virustotal.des', {
        defaultMessage: 'Alerts resulting from VirusTotal analysis of suspicious files via an integration with their API.',
      })
  },
  mitre: {
    title: i18n.translate('mywazuh.overview.mitre.title', {
      defaultMessage: 'MITRE ATT&CK',
    }),
    description:
      i18n.translate('mywazuh.overview.mitre.des', {
        defaultMessage: 'Security events from the knowledge base of adversary tactics and techniques based on real-world observations',
      })
  },
  syscollector: {
    title: i18n.translate('mywazuh.overview.syscollector.title', {
      defaultMessage: 'Inventory data',
    }),
    description:
      i18n.translate('mywazuh.overview.syscollector.des', {
        defaultMessage: 'Applications, network configuration, open ports and processes running on your monitored systems.',
      })
  },
  stats: {
    title: i18n.translate('mywazuh.overview.stats.title', {
      defaultMessage: 'Stats',
    }),
    description: i18n.translate('mywazuh.overview.stats.des', {
      defaultMessage: 'Stats for agent and logcollector',
    })
  },
  configuration: {
    title: i18n.translate('mywazuh.overview.configuration.title', {
      defaultMessage: 'Configuration',
    }),
    description:
      i18n.translate('mywazuh.overview.configuration.des', {
        defaultMessage: 'Check the current agent configuration remotely applied by its group.',
      })
  },
  osquery: {
    title: i18n.translate('mywazuh.overview.osquery.title', {
      defaultMessage: 'Osquery',
    }),
    description:
      i18n.translate('mywazuh.overview.osquery.des', {
        defaultMessage: 'Osquery can be used to expose an operating system as a high-performance relational database.',
      })
  },
  sca: {
    title: i18n.translate('mywazuh.overview.sca.title', {
      defaultMessage: 'Security configuration assessment',
    }),
    description: i18n.translate('mywazuh.overview.sca.des', {
      defaultMessage: 'Scan your assets as part of a configuration assessment audit.',
    })
  },
  docker: {
    title: i18n.translate('mywazuh.overview.docker.title', {
      defaultMessage: 'Docker listener',
    }),
    description:
      i18n.translate('mywazuh.overview.docker.des', {
        defaultMessage: 'Monitor and collect the activity from Docker containers such as creation, running, starting, stopping or pausing events.',
      })
  },
  github: {
    title: i18n.translate('mywazuh.overview.github.title', {
      defaultMessage: 'GitHub',
    }),
    description:
      i18n.translate('mywazuh.overview.github.des', {
        defaultMessage: 'Monitoring events from audit logs of your GitHub organizations.',
      })
  },
  devTools: {
    title: i18n.translate('mywazuh.overview.devTools.title', {
      defaultMessage: 'API console',
    }),
    description: i18n.translate('mywazuh.overview.devTools.des', {
      defaultMessage: 'Test the Wazuh API endpoints.',
    })
  },
  logtest: {
    title: i18n.translate('mywazuh.overview.logtest.title', {
      defaultMessage: 'Test your logs',
    }),
    description: i18n.translate('mywazuh.overview.logtest.des', {
      defaultMessage: 'Check your ruleset testing logs.',
    })
  },
  testConfiguration: {
    title: i18n.translate('mywazuh.overview.testConfiguration.title', {
      defaultMessage: 'Test your configurations',
    }),
    description: i18n.translate('mywazuh.overview.testConfiguration.des', {
      defaultMessage: 'Check configurations before applying them',
    })
  }
};
