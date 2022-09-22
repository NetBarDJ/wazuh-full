/*
 * Wazuh app - Agent vulnerabilities components
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */

import React, {Component} from 'react';
import {
  EuiCard,
  EuiFlexGroup,
  EuiFlexItem,
  EuiPage,
  EuiPageBody,
  euiPaletteColorBlind,
  EuiPanel,
  EuiProgress,
  EuiSpacer,
  EuiStat,
  EuiToolTip,
} from '@elastic/eui';
import {EuiPalette} from '@elastic/eui/src/services/color/eui_palettes';
import {InventoryTable,} from './inventory/';
import {getAggregation, getLastScan} from './inventory/lib';
import {ICustomBadges} from '../../wz-search-bar/components';
import {formatUIDate} from '../../../react-services';
import {VisualizationBasicWidget, VisualizationBasicWidgetSelector} from '../../common/charts/visualizations/basic';
import {WzStat} from '../../wz-stat';
import {i18n} from '@kbn/i18n';

interface Aggregation {
  title: number,
  description: string,
  titleColor: string
}

interface pieStats {
  id: string,
  label: string,
  value: number
}

interface LastScan {
  last_full_scan: string,
  last_partial_scan: string
}

interface TitleColors {
  Critical: string,
  High: string,
  Medium: string,
  Low: string
}

export class Inventory extends Component {
  _isMount = false;
  state: {
    filters: [];
    isLoading: boolean;
    isLoadingStats: boolean;
    customBadges: ICustomBadges[];
    stats: Aggregation[],
    severityPieStats: pieStats[],
    vulnerabilityLastScan: LastScan,
  };
  props: any;
  colorsVisualizationVulnerabilitiesSummaryData: EuiPalette;
  titleColors: TitleColors = {Critical: '#BD271E', High: '#d5a612', Medium: '#006BB4', Low: '#6a717d'};

  constructor(props) {
    super(props);
    this.state = {
      isLoading: true,
      isLoadingStats: true,
      customBadges: [],
      filters: [],
      stats: [
        {title: 0, description: 'Critical', titleColor: this.titleColors.Critical},
        {title: 0, description: 'High', titleColor: this.titleColors.High},
        {title: 0, description: 'Medium', titleColor: this.titleColors.Medium},
        {title: 0, description: 'Low', titleColor: this.titleColors.Low},
      ],
      severityPieStats: [],
      vulnerabilityLastScan: {
        last_full_scan: '',
        last_partial_scan: ''
      },
    }
    this.fetchVisualizationVulnerabilitiesSummaryData = this.fetchVisualizationVulnerabilitiesSummaryData.bind(this);
    this.fetchVisualizationVulnerabilitiesSeverityData = this.fetchVisualizationVulnerabilitiesSeverityData.bind(this);
    this.colorsVisualizationVulnerabilitiesSummaryData = euiPaletteColorBlind();
  }

  async componentDidMount() {
    this._isMount = true;
    await this.loadAgent();
  }

  componentWillUnmount() {
    this._isMount = false;
  }

  async fetchVisualizationVulnerabilitiesSummaryData(field, agentID) {
    const results = await getAggregation(agentID, field, 4);
    return Object.entries(results[field]).map(([key, value], index) => ({
      label: key,
      value,
      color: this.colorsVisualizationVulnerabilitiesSummaryData[index],
      onClick: () => this.onFiltersChange(this.buildFilterQuery(field, key))
    })).sort((firstElement, secondElement) => secondElement.value - firstElement.value)
  }

  async fetchVisualizationVulnerabilitiesSeverityData() {
    const {id} = this.props.agent;
    const FIELD = 'severity';
    const SEVERITY_KEYS = [i18n.translate('public.components.agents.vuls.severity.Critical', {
      defaultMessage: 'Critical',
    }),
      i18n.translate('public.components.agents.vuls.severity.High', {
        defaultMessage: 'High',
      }),
      i18n.translate('public.components.agents.vuls.severity.Medium', {
        defaultMessage: 'Medium',
      }),
      i18n.translate('public.components.agents.vuls.severity.Low', {
        defaultMessage: 'Low',
      })];
    this.setState({isLoadingStats: true});

    const vulnerabilityLastScan = await getLastScan(id);
    const {severity} = await getAggregation(id, FIELD);

    const severityStats = SEVERITY_KEYS.map(key => ({
      titleColor: this.titleColors[key],
      description: key,
      title: severity[key] ? severity[key] : 0
    }));

    this.setState({
      stats: severityStats,
      isLoadingStats: false,
      vulnerabilityLastScan
    });

    return Object.keys(severity).length ? SEVERITY_KEYS.map(key => ({
      label: key,
      value: severity[key] ? severity[key] : 0,
      color: this.titleColors[key],
      onClick: () => this.onFiltersChange(this.buildFilterQuery(FIELD, key))
    })) : [];
  }

  buildFilterQuery(field = '', selectedItem = '') {
    return [
      {
        field: 'q',
        value: `${field}=${selectedItem}`,
      },
    ]
  }

  async loadAgent() {
    if (this._isMount) {
      this.setState({
        isLoading: false
      });
    }
  }

  onFiltersChange = (filters) => {
    this.setState({filters});
  }

  renderTable() {
    const {filters} = this.state;
    return (
      <div>
        <InventoryTable
          {...this.props}
          filters={filters}
          onFiltersChange={this.onFiltersChange}
        />
      </div>
    )
  }

  loadingInventory() {
    return <EuiPage>
      <EuiFlexGroup>
        <EuiFlexItem>
          <EuiProgress size="xs" color="primary"/>
        </EuiFlexItem>
      </EuiFlexGroup>
    </EuiPage>;
  }

  // This method was created because Wazuh API returns 1970-01-01T00:00:00Z dates or undefined ones
  // when vulnerability module is not configured
  // its meant to render nothing when such date is received
  beautifyDate(date?: string) {
    return date && !['1970-01-01T00:00:00Z', '-'].includes(date) ? formatUIDate(date) : '-';
  }

  buildTitleFilter({description, title, titleColor}) {
    const {isLoadingStats} = this.state;
    return (
      <EuiFlexItem
        key={`module_vulnerabilities_inventory_stat_${description}`}
      >
        <EuiStat
          textAlign='center'
          isLoading={isLoadingStats}
          title={(
            <EuiToolTip position="top" content={`Filter by Severity`}>
              <span
                className={'statWithLink wz-user-select-none'}
                style={{cursor: 'pointer', fontSize: '2.25rem'}}
                onClick={() => this.onFiltersChange(this.buildFilterQuery('severity', description))}
              >
                {title}
              </span>
            </EuiToolTip>
          )}
          description={description}
          titleColor={titleColor}
        />
      </EuiFlexItem>
    )
  }

  render() {
    const {isLoading, stats, vulnerabilityLastScan} = this.state;
    if (isLoading) {
      return this.loadingInventory()
    }
    const last_full_scan = this.beautifyDate(vulnerabilityLastScan.last_full_scan);
    const last_partial_scan = this.beautifyDate(vulnerabilityLastScan.last_partial_scan);

    const table = this.renderTable();
    return <EuiPage>
      <EuiPageBody>
        <EuiFlexGroup wrap>
          <EuiFlexItem>
            <EuiCard title description betaBadgeLabel="严重性"
                     className="wz-euiCard-no-title wz-euiCard-children-full-height">
              <div style={{display: 'flex', alignItems: 'flex-end', height: '100%'}}>
                <VisualizationBasicWidget
                  type='donut'
                  size={{width: '100%', height: '150px'}}
                  showLegend
                  onFetch={this.fetchVisualizationVulnerabilitiesSeverityData}
                  onFetchDependencies={[this.props.agent.id]}
                  noDataTitle='没有数据'
                  noDataMessage='没有找到数据'
                />
              </div>
            </EuiCard>
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiCard title description betaBadgeLabel="详情">
              <EuiFlexGroup alignItems="center" className={"height-full"}>
                <EuiFlexItem>
                  <EuiFlexGroup alignItems="center">
                    {stats.map((stat) => this.buildTitleFilter(stat))}
                  </EuiFlexGroup>
                  <EuiFlexGroup style={{marginTop: 'auto'}}>
                    <EuiFlexItem>
                      <WzStat
                        title={last_full_scan}
                        description="上次完整扫描"
                        textAlign='center'
                        titleSize='xs'
                      />
                    </EuiFlexItem>
                    <EuiFlexItem>
                      <WzStat
                        title={last_partial_scan}
                        description="上次部分扫描"
                        textAlign='center'
                        titleSize='xs'
                      />
                    </EuiFlexItem>
                  </EuiFlexGroup>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiCard>
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiCard title description betaBadgeLabel="总结" className="wz-euiCard-no-title">
              <VisualizationBasicWidgetSelector
                type='donut'
                size={{width: '100%', height: '150px'}}
                showLegend
                selectorOptions={[
                  {value: 'name', text: 'Name'},
                  {value: 'cve', text: 'CVE'},
                  {value: 'version', text: 'Version'},
                  {value: 'cvss2_score', text: 'CVSS2 Score'},
                  {value: 'cvss3_score', text: 'CVSS3 Score'}
                ]}
                onFetch={this.fetchVisualizationVulnerabilitiesSummaryData}
                onFetchExtraDependencies={[this.props.agent.id]}
                noDataTitle='没有数据'
                noDataMessage={(_, optionRequirement) => `没有 ${optionRequirement.text} 相关的数据`}
              />
            </EuiCard>
          </EuiFlexItem>
        </EuiFlexGroup>
        <EuiSpacer/>
        <EuiPanel>
          {table}
        </EuiPanel>
      </EuiPageBody>
    </EuiPage>
  }
}
