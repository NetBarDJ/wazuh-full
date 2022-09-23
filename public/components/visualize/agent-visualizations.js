/*
 * Wazuh app - Agents visualizations
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

export const agentVisualizations = {
  general: {
    rows: [
      {
        height: 400,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-General-Alert-groups-evolution', {
              defaultMessage: 'Alert groups evolution',
            }),
            id: 'Wazuh-App-Agents-General-Alert-groups-evolution',
            width: 50
          },
          {title: 'Alerts', id: 'Wazuh-App-Agents-General-Alerts', width: 50}
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-General-Top-5-alerts', {
              defaultMessage: 'Top 5 alerts',
            }),
            id: 'Wazuh-App-Agents-General-Top-5-alerts',
            width: 33
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-General-Top-10-groups', {
              defaultMessage: 'Top 5 rule groups',
            }),
            id: 'Wazuh-App-Agents-General-Top-10-groups',
            width: 33
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-General-Top-5-PCI-DSS-Requirements', {
              defaultMessage: 'Top 5 PCI DSS Requirements',
            }),
            id: 'Wazuh-App-Agents-General-Top-5-PCI-DSS-Requirements',
            width: 34
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-General-Alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Agents-General-Alerts-summary',
            width: 60
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-General-Groups-summary', {
              defaultMessage: 'Groups summary',
            }),
            id: 'Wazuh-App-Agents-General-Groups-summary',
            width: 40
          }
        ]
      }
    ]
  },
  aws: {
    rows: [
      {
        height: 250,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-AWS-Top-sources', {
              defaultMessage: 'Sources',
            }),
            id: 'Wazuh-App-Agents-AWS-Top-sources',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-AWS-Top-accounts', {
              defaultMessage: 'Accounts',
            }),
            id: 'Wazuh-App-Agents-AWS-Top-accounts',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-AWS-Top-buckets', {
              defaultMessage: 'S3 buckets',
            }),
            id: 'Wazuh-App-Agents-AWS-Top-buckets',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-AWS-Top-regions', {
              defaultMessage: 'Regions',
            }),
            id: 'Wazuh-App-Agents-AWS-Top-regions',
            width: 25
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-AWS-Events-by-source', {
              defaultMessage: 'Events by source over time',
            }),
            id: 'Wazuh-App-Agents-AWS-Events-by-source',
            width: 50
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-AWS-Events-by-s3-bucket', {
              defaultMessage: 'Events by S3 bucket over time',
            }),
            id: 'Wazuh-App-Agents-AWS-Events-by-s3-bucket',
            width: 50
          }
        ]
      },
      {
        height: 570,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-AWS-geo', {
              defaultMessage: 'Geolocation map',
            }),
            id: 'Wazuh-App-Agents-AWS-geo'
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-AWS-Alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Agents-AWS-Alerts-summary'
          }
        ]
      }
    ]
  },
  fim: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-FIM-Users', {
              defaultMessage: 'Most active users',
            }),
            id: 'Wazuh-App-Agents-FIM-Users',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-FIM-Actions', {
              defaultMessage: 'Actions',
            }),
            id: 'Wazuh-App-Agents-FIM-Actions',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-FIM-Events', {
              defaultMessage: 'Events',
            }),
            id: 'Wazuh-App-Agents-FIM-Events',
            width: 50
          }
        ]
      },
      {
        height: 230,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-FIM-Files-added', {
              defaultMessage: 'Files added',
            }),
            id: 'Wazuh-App-Agents-FIM-Files-added',
            width: 33
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-FIM-Files-modified', {
              defaultMessage: 'Files modified',
            }),
            id: 'Wazuh-App-Agents-FIM-Files-modified',
            width: 33
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-FIM-Files-deleted', {
              defaultMessage: 'Files deleted',
            }),
            id: 'Wazuh-App-Agents-FIM-Files-deleted',
            width: 34
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-FIM-Alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Agents-FIM-Alerts-summary'
          }
        ]
      }
    ]
  },
  gcp: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-GCP-Top-5-rules', {
              defaultMessage: 'Top 5 rules',
            }),
            id: 'Wazuh-App-Agents-GCP-Top-5-rules',
            width: 50
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-GCP-Event-Query-Name', {
              defaultMessage: 'Top query events',
            }),
            id: 'Wazuh-App-Agents-GCP-Event-Query-Name',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-GCP-Top-5-instances', {
              defaultMessage: 'Top 5 instances',
            }),
            id: 'Wazuh-App-Agents-GCP-Top-5-instances',
            width: 25
          },
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-GCP-Top-ProjectId-By-SourceType', {
              defaultMessage: 'Top project id by sourcetype',
            }),
            id: 'Wazuh-App-Agents-GCP-Top-ProjectId-By-SourceType',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-GCP-Events-Over-Time', {
              defaultMessage: 'GCP alerts evolution',
            }),
            id: 'Wazuh-App-Agents-GCP-Events-Over-Time',
            width: 75
          },
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-GCP-authAnswer-Bar', {
              defaultMessage: 'Auth answer count',
            }),
            id: 'Wazuh-App-Agents-GCP-authAnswer-Bar',
            width: 40
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-GCP-Top-ResourceType-By-Project-Id', {
              defaultMessage: 'Resource type by project id',
            }),
            id: 'Wazuh-App-Agents-GCP-Top-ResourceType-By-Project-Id',
            width: 60
          },
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-GCP-Alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Agents-GCP-Alerts-summary'
          }
        ]
      }
    ]
  },
  pci: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-PCI-Groups', {
              defaultMessage: 'Top 5 rule groups',
            }),
            id: 'Wazuh-App-Agents-PCI-Groups',
            width: 33
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-PCI-Rule', {
              defaultMessage: 'Top 5 rules',
            }),
            id: 'Wazuh-App-Agents-PCI-Rule',
            width: 33
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-PCI-Requirement', {
              defaultMessage: 'Top 5 PCI DSS requirements',
            }),
            id: 'Wazuh-App-Agents-PCI-Requirement',
            width: 34
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-PCI-Requirements', {
              defaultMessage: 'PCI Requirements',
            }),
            id: 'Wazuh-App-Agents-PCI-Requirements',
            width: 75
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-PCI-Rule-level-distribution', {
              defaultMessage: 'Rule level distribution',
            }),
            id: 'Wazuh-App-Agents-PCI-Rule-level-distribution',
            width: 25
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-PCI-Last-alerts', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Agents-PCI-Last-alerts'
          }
        ]
      }
    ]
  },
  gdpr: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-GDPR-Groups', {
              defaultMessage: 'Top 5 rule groups',
            }),
            id: 'Wazuh-App-Agents-GDPR-Groups',
            width: 33
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-GDPR-Rule', {
              defaultMessage: 'Top 5 rules',
            }),
            id: 'Wazuh-App-Agents-GDPR-Rule',
            width: 33
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-GDPR-Requirement', {
              defaultMessage: 'Top 5 GDPR requirements',
            }),
            id: 'Wazuh-App-Agents-GDPR-Requirement',
            width: 34
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-GDPR-Requirements', {
              defaultMessage: 'GDPR Requirements',
            }),
            id: 'Wazuh-App-Agents-GDPR-Requirements',
            width: 75
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-GDPR-Rule-level-distribution', {
              defaultMessage: 'Rule level distribution',
            }),
            id: 'Wazuh-App-Agents-GDPR-Rule-level-distribution',
            width: 25
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-GDPR-Last-alerts', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Agents-GDPR-Last-alerts'
          }
        ]
      }
    ]
  },
  nist: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-NIST-Stats', {
              defaultMessage: 'Stats',
            }),
            id: 'Wazuh-App-Agents-NIST-Stats',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-NIST-top-10-requirements', {
              defaultMessage: 'Top 10 requirements',
            }),
            id: 'Wazuh-App-Agents-NIST-top-10-requirements',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-NIST-Requirement-by-level', {
              defaultMessage: 'Requirements distributed by level',
            }),
            id: 'Wazuh-App-Agents-NIST-Requirement-by-level',
            width: 50
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-NIST-Requirements-stacked-overtime', {
              defaultMessage: 'Requirements over time',
            }),
            id: 'Wazuh-App-Agents-NIST-Requirements-stacked-overtime'
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-NIST-Last-alerts', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Agents-NIST-Last-alerts'
          }
        ]
      }
    ]
  },
  tsc: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-TSC-Groups', {
              defaultMessage: 'Top 5 rule groups',
            }),
            id: 'Wazuh-App-Agents-TSC-Groups',
            width: 33
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-TSC-Rule', {
              defaultMessage: 'Top 5 rules',
            }),
            id: 'Wazuh-App-Agents-TSC-Rule',
            width: 33
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-TSC-Requirement', {
              defaultMessage: 'Top 5 TSC requirements',
            }),
            id: 'Wazuh-App-Agents-TSC-Requirement',
            width: 34
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-TSC-Requirements', {
              defaultMessage: 'TSC Requirements',
            }),
            id: 'Wazuh-App-Agents-TSC-Requirements',
            width: 75
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-TSC-Rule-level-distribution', {
              defaultMessage: 'Rule level distribution',
            }),
            id: 'Wazuh-App-Agents-TSC-Rule-level-distribution',
            width: 25
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Overview-TSC-Alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Overview-TSC-Alerts-summary'
          }
        ]
      }
    ]
  },
  hipaa: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-HIPAA-Requirements-Stacked-Overtime', {
              defaultMessage: 'Requirements over time',
            }),
            id: 'Wazuh-App-Agents-HIPAA-Requirements-Stacked-Overtime',
            width: 50
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-HIPAA-top-10', {
              defaultMessage: 'Top 10 requirements',
            }),
            id: 'Wazuh-App-Agents-HIPAA-top-10',
            width: 50
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-HIPAA-Burbles', {
              defaultMessage: 'HIPAA requirements',
            }),
            id: 'Wazuh-App-Agents-HIPAA-Burbles',
            width: 50
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-HIPAA-Distributed-By-Level', {
              defaultMessage: 'Requirements distribution by level',
            }),
            id: 'Wazuh-App-Agents-HIPAA-Distributed-By-Level',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-HIPAA-Most-Common', {
              defaultMessage: 'Most common alerts',
            }),
            id: 'Wazuh-App-Agents-HIPAA-Most-Common',
            width: 25
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-HIPAA-Last-alerts', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Agents-HIPAA-Last-alerts'
          }
        ]
      }
    ]
  },
  virustotal: {
    rows: [
      {
        height: 250,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-Virustotal-Last-Files-Pie', {
              defaultMessage: 'Last scanned files',
            }),
            id: 'Wazuh-App-Agents-Virustotal-Last-Files-Pie',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-Virustotal-Malicious-Evolution', {
              defaultMessage: 'Malicious files alerts Evolution',
            }),
            id: 'Wazuh-App-Agents-Virustotal-Malicious-Evolution',
            width: 75
          }
        ]
      },
      {
        height: 570,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-Virustotal-Files-Table', {
              defaultMessage: 'Last files',
            }),
            id: 'Wazuh-App-Agents-Virustotal-Files-Table'
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-Virustotal-Alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Agents-Virustotal-Alerts-summary'
          }
        ]
      }
    ]
  },
  osquery: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-Osquery-most-common-osquery-actions', {
              defaultMessage: 'Most common Osquery actions',
            }),
            id: 'Wazuh-App-Agents-Osquery-most-common-osquery-actions',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-Osquery-Evolution', {
              defaultMessage: 'Evolution of Osquery events per pack over time',
            }),
            id: 'Wazuh-App-Agents-Osquery-Evolution',
            width: 75
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-Osquery-top-5-packs-being-used', {
              defaultMessage: 'Most common Osquery packs being used',
            }),
            id: 'Wazuh-App-Agents-Osquery-top-5-packs-being-used',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-Osquery-monst-common-rules-being-fired', {
              defaultMessage: 'Most common rules',
            }),
            id: 'Wazuh-App-Agents-Osquery-monst-common-rules-being-fired',
            width: 75
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Overview-Osquery-Alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Overview-Osquery-Alerts-summary'
          }
        ]
      }
    ]
  },
  mitre: {
    rows: [
      {
        height: 360,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-MITRE-Alerts-Evolution', {
              defaultMessage: 'Alerts evolution over time',
            }),
            id: 'Wazuh-App-Agents-MITRE-Alerts-Evolution',
            width: 70
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-MITRE-Top-Tactics', {
              defaultMessage: 'Top tactics',
            }),
            id: 'Wazuh-App-Agents-MITRE-Top-Tactics',
            width: 30
          }
        ]
      },
      {
        height: 360,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-MITRE-Level-By-Attack', {
              defaultMessage: 'Rule level by attack',
            }),
            id: 'Wazuh-App-Agents-MITRE-Level-By-Attack',
            width: 33
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-MITRE-Attacks-By-Tactic', {
              defaultMessage: 'MITRE attacks by tactic',
            }),
            id: 'Wazuh-App-Agents-MITRE-Attacks-By-Tactic',
            width: 34
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-MITRE-Level-By-Tactic', {
              defaultMessage: 'Rule level by tactic',
            }),
            id: 'Wazuh-App-Agents-MITRE-Level-By-Tactic',
            width: 34
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-MITRE-Alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Agents-MITRE-Alerts-summary'
          }
        ]
      }
    ]
  },
  docker: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-Docker-top-5-images', {
              defaultMessage: 'Top 5 images',
            }),
            id: 'Wazuh-App-Agents-Docker-top-5-images',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-Docker-top-5-actions', {
              defaultMessage: 'Top 5 events',
            }),
            id: 'Wazuh-App-Agents-Docker-top-5-actions',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-Docker-Types-over-time', {
              defaultMessage: 'Resources usage over time',
            }),
            id: 'Wazuh-App-Agents-Docker-Types-over-time',
            width: 50
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-Docker-Actions-over-time', {
              defaultMessage: 'Events occurred evolution',
            }),
            id: 'Wazuh-App-Agents-Docker-Actions-over-time'
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-Docker-Events-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Agents-Docker-Events-summary'
          }
        ]
      }
    ]
  },
  oscap: {
    rows: [
      {
        height: 230,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-OSCAP-Scans', {
              defaultMessage: 'Top 5 Scans',
            }),
            id: 'Wazuh-App-Agents-OSCAP-Scans',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-OSCAP-Profiles', {
              defaultMessage: 'Top 5 Profiles',
            }),
            id: 'Wazuh-App-Agents-OSCAP-Profiles',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-OSCAP-Content', {
              defaultMessage: 'Top 5 Content',
            }),
            id: 'Wazuh-App-Agents-OSCAP-Content',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-OSCAP-Severity', {
              defaultMessage: 'Top 5 Severity',
            }),
            id: 'Wazuh-App-Agents-OSCAP-Severity',
            width: 25
          }
        ]
      },
      {
        height: 230,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-OSCAP-Daily-scans-evolution', {
              defaultMessage: 'Daily scans evolution',
            }),
            id: 'Wazuh-App-Agents-OSCAP-Daily-scans-evolution'
          }
        ]
      },
      {
        height: 250,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-OSCAP-Top-5-Alerts', {
              defaultMessage: 'Top 5 - Alerts',
            }),
            id: 'Wazuh-App-Agents-OSCAP-Top-5-Alerts',
            width: 50
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-OSCAP-Top-5-High-risk-alerts', {
              defaultMessage: 'Top 5 - High risk alerts',
            }),
            id: 'Wazuh-App-Agents-OSCAP-Top-5-High-risk-alerts',
            width: 50
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-OSCAP-Last-alerts', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Agents-OSCAP-Last-alerts'
          }
        ]
      }
    ]
  },
  ciscat: {
    rows: [
      {
        height: 320,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-app-Agents-CISCAT-top-5-groups', {
              defaultMessage: 'Top 5 CIS-CAT groups',
            }),
            id: 'Wazuh-app-Agents-CISCAT-top-5-groups',
            width: 60
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-app-Agents-CISCAT-scan-result-evolution', {
              defaultMessage: 'Scan result evolution',
            }),
            id: 'Wazuh-app-Agents-CISCAT-scan-result-evolution',
            width: 40
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-app-Agents-CISCAT-alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-app-Agents-CISCAT-alerts-summary'
          }
        ]
      }
    ]
  },
  pm: {
    rows: [
      {
        height: 290,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-PM-Events-over-time', {
              defaultMessage: 'Alerts over time',
            }),
            id: 'Wazuh-App-Agents-PM-Events-over-time',
            width: 50
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-PM-Top-5-rules', {
              defaultMessage: 'Rule distribution',
            }),
            id: 'Wazuh-App-Agents-PM-Top-5-rules',
            width: 50
          }
        ]
      },
      {
        height: 240,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-PM-Events-per-agent-evolution', {
              defaultMessage: 'Events per control type evolution',
            }),
            id: 'Wazuh-App-Agents-PM-Events-per-agent-evolution'
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-PM-Alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Agents-PM-Alerts-summary'
          }
        ]
      }
    ]
  },
  audit: {
    rows: [
      {
        height: 250,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-Audit-Groups', {
              defaultMessage: 'Groups',
            }),
            id: 'Wazuh-App-Agents-Audit-Groups',
            width: 33
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-Audit-Commands', {
              defaultMessage: 'Commands',
            }),
            id: 'Wazuh-App-Agents-Audit-Commands',
            width: 33
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-Audit-Files', {
              defaultMessage: 'Files',
            }),
            id: 'Wazuh-App-Agents-Audit-Files',
            width: 34
          }
        ]
      },
      {
        height: 310,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-Audit-Alerts-over-time', {
              defaultMessage: 'Alerts over time',
            }),
            id: 'Wazuh-App-Agents-Audit-Alerts-over-time'
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Agents-Audit-Last-alerts', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Agents-Audit-Last-alerts'
          }
        ]
      }
    ]
  },
  github: {
    rows: [
      {
        height: 360,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Overview-GitHub-Alerts-Evolution-By-Organization', {
              defaultMessage: 'Alerts evolution by organization',
            }),
            id: 'Wazuh-App-Overview-GitHub-Alerts-Evolution-By-Organization',
            width: 60
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Overview-GitHub-Top-5-Organizations-By-Alerts', {
              defaultMessage: 'Top 5 organizations by alerts',
            }),
            id: 'Wazuh-App-Overview-GitHub-Top-5-Organizations-By-Alerts',
            width: 40
          }
        ]
      },
      {
        height: 360,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Overview-GitHub-Alert-Action-Type-By-Organization', {
              defaultMessage: 'Top alerts by action type and organization',
            }),
            id: 'Wazuh-App-Overview-GitHub-Alert-Action-Type-By-Organization',
            width: 40
          },
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Overview-GitHub-Users-With-More-Alerts', {
              defaultMessage: 'Users with more alerts',
            }),
            id: 'Wazuh-App-Overview-GitHub-Users-With-More-Alerts',
            width: 60
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.agent.visualizations.Wazuh-App-Overview-GitHub-Alert-Summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Overview-GitHub-Alert-Summary',
          }
        ]
      }
    ]
  },
};
