/*
 * Wazuh app - Overview visualizations
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

export const visualizations = {
  general: {
    rows: [
      {
        height: 360,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-General-Alert-level-evolution', {
              defaultMessage: 'Alert level evolution',
            }),
            id: 'Wazuh-App-Overview-General-Alert-level-evolution',
            width: 60
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-General-Alerts-Top-Mitre', {
              defaultMessage: 'Top MITRE ATT&CKS',
            }),
            id: 'Wazuh-App-Overview-General-Alerts-Top-Mitre',
            width: 40
          }
        ]
      },
      {
        height: 360,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-General-Top-5-agents', {
              defaultMessage: 'Top 5 agents',
            }),
            id: 'Wazuh-App-Overview-General-Top-5-agents',
            width: 30
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-General-Alerts-evolution-Top-5-agents', {
              defaultMessage: 'Alerts evolution - Top 5 agents',
            }),
            id: 'Wazuh-App-Overview-General-Alerts-evolution-Top-5-agents',
            width: 70
          },
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-General-Alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Overview-General-Alerts-summary'
          }
        ]
      }
    ]
  },
  fim: {
    rows: [
      {
        height: 400,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Agents-FIM-Alerts-by-action-over-time', {
              defaultMessage: 'Alerts by action over time',
            }),
            id: 'Wazuh-App-Agents-FIM-Alerts-by-action-over-time'
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-FIM-Top-5-agents-pie', {
              defaultMessage: 'Top 5 agents',
            }),
            id: 'Wazuh-App-Overview-FIM-Top-5-agents-pie',
            width: 30
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-FIM-Events-summary', {
              defaultMessage: 'Events summary',
            }),
            id: 'Wazuh-App-Overview-FIM-Events-summary',
            width: 70
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-FIM-Top-5-rules', {
              defaultMessage: 'Rule distribution',
            }),
            id: 'Wazuh-App-Overview-FIM-Top-5-rules',
            width: 33
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-FIM-Common-actions', {
              defaultMessage: 'Actions',
            }),
            id: 'Wazuh-App-Overview-FIM-Common-actions',
            width: 33
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-FIM-top-agents-user', {
              defaultMessage: 'Top 5 users',
            }),
            id: 'Wazuh-App-Overview-FIM-top-agents-user',
            width: 34
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-FIM-Alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Overview-FIM-Alerts-summary'
          }
        ]
      }
    ]
  },
  office: {
    rows: [
      {
        height: 320,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Office-Rule-Level-Histogram', {
              defaultMessage: 'Events by severity over time',
            }),
            id: 'Wazuh-App-Overview-Office-Rule-Level-Histogram',
            width: 40
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Office-IPs-By-User-Barchart', {
              defaultMessage: 'IP by Users',
            }),
            id: 'Wazuh-App-Overview-Office-IPs-By-User-Barchart',
            width: 30
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Office-Top-Users-By-Subscription-Barchart', {
              defaultMessage: 'Top Users By Subscription',
            }),
            id: 'Wazuh-App-Overview-Office-Top-Users-By-Subscription-Barchart',
            width: 30
          },
        ]
      },
      {
        height: 350,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Office-User-By-Operation-Result', {
              defaultMessage: 'Users by Operation Result',
            }),
            id: 'Wazuh-App-Overview-Office-User-By-Operation-Result',
            width: 35
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Office-Severity-By-User-Barchart', {
              defaultMessage: 'Severity by User',
            }),
            id: 'Wazuh-App-Overview-Office-Severity-By-User-Barchart',
            width: 30
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Office-Rule-Description-Level-Table', {
              defaultMessage: 'Rule Description by Level',
            }),
            id: 'Wazuh-App-Overview-Office-Rule-Description-Level-Table',
            width: 35
          },
        ]
      },
      {
        height: 570,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Office-Location', {
              defaultMessage: 'Geolocation map',
            }),
            id: 'Wazuh-App-Overview-Office-Location'
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Office-Alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Overview-Office-Alerts-summary'
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
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-AWS-Top-sources', {
              defaultMessage: 'Sources',
            }),
            id: 'Wazuh-App-Overview-AWS-Top-sources',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-AWS-Top-accounts', {
              defaultMessage: 'Accounts',
            }),
            id: 'Wazuh-App-Overview-AWS-Top-accounts',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-AWS-Top-buckets', {
              defaultMessage: 'S3 buckets',
            }),
            id: 'Wazuh-App-Overview-AWS-Top-buckets',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-AWS-Top-regions', {
              defaultMessage: 'Regions',
            }),
            id: 'Wazuh-App-Overview-AWS-Top-regions',
            width: 25
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-AWS-Events-by-source', {
              defaultMessage: 'Events by source over time',
            }),
            id: 'Wazuh-App-Overview-AWS-Events-by-source',
            width: 50
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-AWS-Events-by-s3-bucket', {
              defaultMessage: 'Events by S3 bucket over time',
            }),
            id: 'Wazuh-App-Overview-AWS-Events-by-s3-bucket',
            width: 50
          }
        ]
      },
      {
        height: 570,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-AWS-geo', {
              defaultMessage: 'Geolocation map',
            }),
            id: 'Wazuh-App-Overview-AWS-geo'
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-AWS-Alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Overview-AWS-Alerts-summary'
          }
        ]
      }
    ]
  },
  gcp: {
    rows: [
      {
        height: 250,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-GCP-Alerts-Evolution-By-AuthAnswer', {
              defaultMessage: 'Events over time by auth answer',
            }),
            id: 'Wazuh-App-Overview-GCP-Alerts-Evolution-By-AuthAnswer',
            width: 100
          }
        ]
      },
      {
        height: 250,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-GCP-Top-vmInstances-By-ResponseCode', {
              defaultMessage: 'Top instances by response code',
            }),
            id: 'Wazuh-App-Overview-GCP-Top-vmInstances-By-ResponseCode',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-GCP-Top-ResourceType-By-Project-Id', {
              defaultMessage: 'Resource type by project id',
            }),
            id: 'Wazuh-App-Overview-GCP-Top-ResourceType-By-Project-Id',
            width: 50
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-GCP-Top-ProjectId-By-SourceType', {
              defaultMessage: 'Top project id by sourcetype',
            }),
            id: 'Wazuh-App-Overview-GCP-Top-ProjectId-By-SourceType',
            width: 25
          },
        ]
      },
      {
        height: 450,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-GCP-Map-By-SourceIp', {
              defaultMessage: 'Top 5 Map by source ip',
            }),
            id: 'Wazuh-App-Overview-GCP-Map-By-SourceIp',
            width: 100
          },
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-GCP-Alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Overview-GCP-Alerts-summary'
          }
        ]
      }
    ]
  },
  pci: {
    rows: [
      {
        height: 400,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-PCI-DSS-requirements', {
              defaultMessage: 'PCI DSS requirements',
            }),
            id: 'Wazuh-App-Overview-PCI-DSS-requirements',
            width: 50
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-PCI-DSS-Agents', {
              defaultMessage: 'Top 10 agents by alerts number',
            }),
            id: 'Wazuh-App-Overview-PCI-DSS-Agents',
            width: 50
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-PCI-DSS-Requirements-over-time', {
              defaultMessage: 'Top requirements over time',
            }),
            id: 'Wazuh-App-Overview-PCI-DSS-Requirements-over-time'
          }
        ]
      },
      {
        height: 530,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-PCI-DSS-Requirements-Agents-heatmap', {
              defaultMessage: 'Last alerts',
            }),
            id: 'Wazuh-App-Overview-PCI-DSS-Requirements-Agents-heatmap'
          }
        ]
      },
      {
        height: 255,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-PCI-DSS-Requirements-by-agent', {
              defaultMessage: 'Requirements by agent',
            }),
            id: 'Wazuh-App-Overview-PCI-DSS-Requirements-by-agent'
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-PCI-DSS-Alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Overview-PCI-DSS-Alerts-summary'
          }
        ]
      }
    ]
  },
  gdpr: {
    rows: [
      {
        height: 400,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-GDPR-Agents', {
              defaultMessage: 'Top 10 agents by alerts number',
            }),
            id: 'Wazuh-App-Overview-GDPR-Agents',
            width: 30
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-GDPR-requirements', {
              defaultMessage: 'GDPR requirements',
            }),
            id: 'Wazuh-App-Overview-GDPR-requirements',
            width: 70
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-GDPR-Requirements-heatmap', {
              defaultMessage: 'Top requirements over time',
            }),
            id: 'Wazuh-App-Overview-GDPR-Requirements-heatmap'
          }
        ]
      },
      {
        height: 530,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-GDPR-Requirements-Agents-heatmap', {
              defaultMessage: 'Last alerts',
            }),
            id: 'Wazuh-App-Overview-GDPR-Requirements-Agents-heatmap'
          }
        ]
      },
      {
        height: 255,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-GDPR-Requirements-by-agent', {
              defaultMessage: 'Requirements by agent',
            }),
            id: 'Wazuh-App-Overview-GDPR-Requirements-by-agent'
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-GDPR-Alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Overview-GDPR-Alerts-summary'
          }
        ]
      }
    ]
  },
  nist: {
    rows: [
      {
        height: 400,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-NIST-Agents', {
              defaultMessage: 'Most active agents',
            }),
            id: 'Wazuh-App-Overview-NIST-Agents',
            width: 20
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-NIST-Requirements-over-time', {
              defaultMessage: 'Top requirements over time',
            }),
            id: 'Wazuh-App-Overview-NIST-Requirements-over-time',
            width: 50
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-NIST-requirements-by-agents', {
              defaultMessage: 'Requiments distribution by agent',
            }),
            id: 'Wazuh-App-Overview-NIST-requirements-by-agents',
            width: 30
          }
        ]
      },
      {
        height: 350,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-NIST-Requirements-Agents-heatmap', {
              defaultMessage: 'Alerts volume by agent',
            }),
            id: 'Wazuh-App-Overview-NIST-Requirements-Agents-heatmap',
            width: 50
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-NIST-Metrics', {
              defaultMessage: 'Stats',
            }),
            id: 'Wazuh-App-Overview-NIST-Metrics',
            width: 20
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-NIST-Top-10-requirements', {
              defaultMessage: 'Top 10 requirements',
            }),
            id: 'Wazuh-App-Overview-NIST-Top-10-requirements',
            width: 30
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-NIST-Alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Overview-NIST-Alerts-summary'
          }
        ]
      }
    ]
  },
  tsc: {
    rows: [
      {
        height: 400,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-TSC-requirements', {
              defaultMessage: 'TSC requirements',
            }),
            id: 'Wazuh-App-Overview-TSC-requirements',
            width: 50
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-TSC-Agents', {
              defaultMessage: 'Top 10 agents by alerts number',
            }),
            id: 'Wazuh-App-Overview-TSC-Agents',
            width: 50
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-TSC-Requirements-over-time', {
              defaultMessage: 'Top requirements over time',
            }),
            id: 'Wazuh-App-Overview-TSC-Requirements-over-time'
          }
        ]
      },
      {
        height: 530,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-TSC-Requirements-Agents-heatmap', {
              defaultMessage: 'Last alerts',
            }),
            id: 'Wazuh-App-Overview-TSC-Requirements-Agents-heatmap'
          }
        ]
      },
      {
        height: 255,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-TSC-Requirements-by-agent', {
              defaultMessage: 'Requirements by agent',
            }),
            id: 'Wazuh-App-Overview-TSC-Requirements-by-agent'
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-TSC-Alerts-summary', {
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
        height: 570,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-HIPAA-Heatmap', {
              defaultMessage: 'Alerts volume by agent',
            }),
            id: 'Wazuh-App-Overview-HIPAA-Heatmap',
            width: 50
          },
          {
            hasRows: true,
            width: 50,
            rows: [
              {
                height: 285,
                vis: [
                  {
                    title: i18n.translate('public.components.visualize.Wazuh-App-Overview-HIPAA-Tag-cloud', {
                      defaultMessage: 'Most common alerts',
                    }),
                    id: 'Wazuh-App-Overview-HIPAA-Tag-cloud',
                    width: 50
                  },
                  {
                    title: i18n.translate('public.components.visualize.Wazuh-App-Overview-HIPAA-Top-10-requirements', {
                      defaultMessage: 'Top 10 requirements',
                    }),
                    id: 'Wazuh-App-Overview-HIPAA-Top-10-requirements',
                    width: 50
                  }
                ]
              },
              {
                height: 285,
                noMargin: true,
                vis: [
                  {
                    title: i18n.translate('public.components.visualize.Wazuh-App-Overview-HIPAA-Top-10-agents', {
                      defaultMessage: 'Most active agents',
                    }),
                    id: 'Wazuh-App-Overview-HIPAA-Top-10-agents',
                    width: 50
                  },
                  {
                    title: i18n.translate('public.components.visualize.Wazuh-App-Overview-HIPAA-Metrics', {
                      defaultMessage: 'Stats',
                    }),
                    id: 'Wazuh-App-Overview-HIPAA-Metrics',
                    width: 50
                  }
                ]
              }
            ]
          }
        ]
      },
      {
        height: 400,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-HIPAA-Top-requirements-over-time', {
              defaultMessage: 'Requirements evolution over time',
            }),
            id: 'Wazuh-App-Overview-HIPAA-Top-requirements-over-time',
            width: 50
          },
          {
            title: 'Requirements distribution by agent',
            id:
              'Wazuh-App-Overview-HIPAA-Top-10-requirements-over-time-by-agent',
            width: 50
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-HIPAA-Alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Overview-HIPAA-Alerts-summary'
          }
        ]
      }
    ]
  },
  vuls: {
    rows: [
      {
        height: 330,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-vuls-Most-affected-agents', {
              defaultMessage: 'Most affected agents',
            }),
            id: 'Wazuh-App-Overview-vuls-Most-affected-agents',
            width: 30
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-vuls-Alerts-severity', {
              defaultMessage: 'Alerts severity',
            }),
            id: 'Wazuh-App-Overview-vuls-Alerts-severity',
            width: 70
          }
        ]
      },
      {
        height: 330,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-vuls-Most-common-CVEs', {
              defaultMessage: 'Most common CVEs',
            }),
            id: 'Wazuh-App-Overview-vuls-Most-common-CVEs',
            width: 30
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-vuls-Vulnerability-evolution-affected-packages', {
              defaultMessage: 'TOP affected packages alerts Evolution',
            }),
            id: 'Wazuh-App-Overview-vuls-Vulnerability-evolution-affected-packages',
            width: 40
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-vuls-Most-common-CWEs', {
              defaultMessage: 'Most common CWEs',
            }),
            id: 'Wazuh-App-Overview-vuls-Most-common-CWEs',
            width: 30
          }
        ]
      },
      {
        height: 450,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-vuls-packages-CVEs', {
              defaultMessage: 'Top affected packages by CVEs',
            }),
            id: 'Wazuh-App-Overview-vuls-packages-CVEs',
            width: 50
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-vuls-agents-severities', {
              defaultMessage: 'Agents by severity',
            }),
            id: 'Wazuh-App-Overview-vuls-agents-severities',
            width: 50
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-vuls-Alert-summary', {
              defaultMessage: 'Alert summary',
            }),
            id: 'Wazuh-App-Overview-vuls-Alert-summary'
          }
        ]
      }
    ]
  },
  virustotal: {
    rows: [
      {
        height: 360,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Virustotal-Malicious-Per-Agent', {
              defaultMessage: 'Unique malicious files per agent',
            }),
            id: 'Wazuh-App-Overview-Virustotal-Malicious-Per-Agent',
            width: 50
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Virustotal-Last-Files-Pie', {
              defaultMessage: 'Last scanned files',
            }),
            id: 'Wazuh-App-Overview-Virustotal-Last-Files-Pie',
            width: 50
          }
        ]
      },
      {
        height: 550,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Virustotal-Alerts-Evolution', {
              defaultMessage: 'Alerts evolution by agents',
            }),
            id: 'Wazuh-App-Overview-Virustotal-Alerts-Evolution'
          }
        ]
      },
      {
        height: 250,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Virustotal-Malicious-Evolution', {
              defaultMessage: 'Malicious files alerts evolution',
            }),
            id: 'Wazuh-App-Overview-Virustotal-Malicious-Evolution'
          }
        ]
      },
      {
        height: 570,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Virustotal-Files-Table', {
              defaultMessage: 'Last files',
            }),
            id: 'Wazuh-App-Overview-Virustotal-Files-Table'
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Virustotal-Alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Overview-Virustotal-Alerts-summary'
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
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Osquery-Top-5-added', {
              defaultMessage: 'Top 5 Osquery events added',
            }),
            id: 'Wazuh-App-Overview-Osquery-Top-5-added',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Osquery-Top-5-removed', {
              defaultMessage: 'Top 5 Osquery events removed',
            }),
            id: 'Wazuh-App-Overview-Osquery-Top-5-removed',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Agents-Osquery-Evolution', {
              defaultMessage: 'Evolution of Osquery events per pack over time',
            }),
            id: 'Wazuh-App-Agents-Osquery-Evolution',
            width: 50
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Osquery-Most-common-packs', {
              defaultMessage: 'Most common packs',
            }),
            id: 'Wazuh-App-Overview-Osquery-Most-common-packs',
            width: 30
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Osquery-Top-5-rules', {
              defaultMessage: 'Top 5 rules',
            }),
            id: 'Wazuh-App-Overview-Osquery-Top-5-rules',
            width: 70
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Osquery-Alerts-summary', {
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
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-MITRE-Alerts-Evolution', {
              defaultMessage: 'Alerts evolution over time',
            }),
            id: 'Wazuh-App-Overview-MITRE-Alerts-Evolution',
            width: 75
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-MITRE-Top-Tactics', {
              defaultMessage: 'Top tactics',
            }),
            id: 'Wazuh-App-Overview-MITRE-Top-Tactics',
            width: 25
          }
        ]
      },
      {
        height: 360,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-MITRE-Attacks-By-Technique', {
              defaultMessage: 'Attacks by technique',
            }),
            id: 'Wazuh-App-Overview-MITRE-Attacks-By-Technique',
            width: 33
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-MITRE-Top-Tactics-By-Agent', {
              defaultMessage: 'Top tactics by agent',
            }),
            id: 'Wazuh-App-Overview-MITRE-Top-Tactics-By-Agent',
            width: 34
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-MITRE-Attacks-By-Agent', {
              defaultMessage: 'Mitre techniques by agent',
            }),
            id: 'Wazuh-App-Overview-MITRE-Attacks-By-Agent',
            width: 33
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-MITRE-Alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Overview-MITRE-Alerts-summary'
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
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Docker-top-5-images', {
              defaultMessage: 'Top 5 images',
            }),
            id: 'Wazuh-App-Overview-Docker-top-5-images',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Docker-top-5-actions', {
              defaultMessage: 'Top 5 events',
            }),
            id: 'Wazuh-App-Overview-Docker-top-5-actions',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Docker-Types-over-time', {
              defaultMessage: 'Resources usage over time',
            }),
            id: 'Wazuh-App-Overview-Docker-Types-over-time',
            width: 50
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Docker-Actions-over-time', {
              defaultMessage: 'Events occurred evolution',
            }),
            id: 'Wazuh-App-Overview-Docker-Actions-over-time'
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Docker-Events-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Overview-Docker-Events-summary'
          }
        ]
      }
    ]
  },
  oscap: {
    rows: [
      {
        height: 215,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-OSCAP-Agents', {
              defaultMessage: 'Top 5 Agents',
            }),
            id: 'Wazuh-App-Overview-OSCAP-Agents',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-OSCAP-Profiles', {
              defaultMessage: 'Top 5 Profiles',
            }),
            id: 'Wazuh-App-Overview-OSCAP-Profiles',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-OSCAP-Content', {
              defaultMessage: 'Top 5 Content',
            }),
            id: 'Wazuh-App-Overview-OSCAP-Content',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-OSCAP-Severity', {
              defaultMessage: 'Top 5 Severity',
            }),
            id: 'Wazuh-App-Overview-OSCAP-Severity',
            width: 25
          }
        ]
      },
      {
        height: 240,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-OSCAP-Top-5-agents-Severity-high', {
              defaultMessage: 'Top 5 Agents - Severity high',
            }),
            id: 'Wazuh-App-Overview-OSCAP-Top-5-agents-Severity-high'
          }
        ]
      },
      {
        height: 320,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-OSCAP-Top-10-alerts', {
              defaultMessage: 'Top 10 - Alerts',
            }),
            id: 'Wazuh-App-Overview-OSCAP-Top-10-alerts',
            width: 50
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-OSCAP-Top-10-high-risk-alerts', {
              defaultMessage: 'Top 10 - High risk alerts',
            }),
            id: 'Wazuh-App-Overview-OSCAP-Top-10-high-risk-alerts',
            width: 50
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-OSCAP-Last-alerts', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Overview-OSCAP-Last-alerts'
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
            title: i18n.translate('public.components.visualize.Wazuh-app-Overview-CISCAT-top-5-groups', {
              defaultMessage: 'Top 5 CIS-CAT groups',
            }),
            id: 'Wazuh-app-Overview-CISCAT-top-5-groups',
            width: 60
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-app-Overview-CISCAT-scan-result-evolution', {
              defaultMessage: 'Scan result evolution',
            }),
            id: 'Wazuh-app-Overview-CISCAT-scan-result-evolution',
            width: 40
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-app-Overview-CISCAT-alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-app-Overview-CISCAT-alerts-summary'
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
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-PM-Events-over-time', {
              defaultMessage: 'Events over time',
            }),
            id: 'Wazuh-App-Overview-PM-Events-over-time',
            width: 50
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-PM-Top-5-rules', {
              defaultMessage: 'Rule distribution',
            }),
            id: 'Wazuh-App-Overview-PM-Top-5-rules',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-PM-Top-5-agents-pie', {
              defaultMessage: 'Top 5 agents',
            }),
            id: 'Wazuh-App-Overview-PM-Top-5-agents-pie',
            width: 25
          }
        ]
      },
      {
        height: 240,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-PM-Events-per-agent-evolution', {
              defaultMessage: 'Events per control type evolution',
            }),
            id: 'Wazuh-App-Overview-PM-Events-per-agent-evolution'
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-PM-Alerts-summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Overview-PM-Alerts-summary'
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
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Audit-Groups', {
              defaultMessage: 'Groups',
            }),
            id: 'Wazuh-App-Overview-Audit-Groups',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Audit-Agents', {
              defaultMessage: 'Agents',
            }),
            id: 'Wazuh-App-Overview-Audit-Agents',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Audit-Commands', {
              defaultMessage: 'Commands',
            }),
            id: 'Wazuh-App-Overview-Audit-Commands',
            width: 25
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Audit-Files', {
              defaultMessage: 'Files',
            }),
            id: 'Wazuh-App-Overview-Audit-Files',
            width: 25
          }
        ]
      },
      {
        height: 310,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Audit-Alerts-over-time', {
              defaultMessage: 'Alerts over time',
            }),
            id: 'Wazuh-App-Overview-Audit-Alerts-over-time'
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-Audit-Last-alerts', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Overview-Audit-Last-alerts'
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
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-GitHub-Alerts-Evolution-By-Organization', {
              defaultMessage: 'Alerts evolution by organization',
            }),
            id: 'Wazuh-App-Overview-GitHub-Alerts-Evolution-By-Organization',
            width: 60
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-GitHub-Top-5-Organizations-By-Alerts', {
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
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-GitHub-Alert-Action-Type-By-Organization', {
              defaultMessage: 'Top alerts by action type and organization',
            }),
            id: 'Wazuh-App-Overview-GitHub-Alert-Action-Type-By-Organization',
            width: 40
          },
          {
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-GitHub-Users-With-More-Alerts', {
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
            title: i18n.translate('public.components.visualize.Wazuh-App-Overview-GitHub-Alert-Summary', {
              defaultMessage: 'Alerts summary',
            }),
            id: 'Wazuh-App-Overview-GitHub-Alert-Summary',
          }
        ]
      }
    ]
  },
};
