import React from 'react';
import {
  EuiBadge,
  EuiBasicTableColumn,
  EuiFlexGroup,
  EuiFlexItem,
  EuiInMemoryTable,
  EuiToolTip,
  SortDirection,
} from '@elastic/eui';
import {ErrorHandler} from '../../../../react-services/error-handler';
import {WzButtonModalConfirm} from '../../../common/buttons';
import {WzAPIUtils} from '../../../../react-services/wz-api-utils';
import RulesServices from '../../rules/services';
import {UI_LOGGER_LEVELS} from '../../../../../common/constants';
import {UI_ERROR_SEVERITIES} from '../../../../react-services/error-orchestrator/types';
import {getErrorOrchestrator} from '../../../../react-services/common-services';
import {i18n} from '@kbn/i18n';

export const RolesMappingTable = ({rolesEquivalences, rules, loading, editRule, updateRules}) => {
  const getRowProps = item => {
    const {id} = item;
    return {
      'data-test-subj': `row-${id}`,
      onClick: () => editRule(item),
    };
  };

  const onDeleteRoleMapping = (item) => {
    return async () => {
      try {
        await RulesServices.DeleteRules([item.id]);
        ErrorHandler.info('Role mapping was successfully deleted');
        updateRules();
      } catch (error) {
        const options = {
          context: `${RolesMappingTable.name}.onDeleteRoleMapping`,
          level: UI_LOGGER_LEVELS.ERROR,
          severity: UI_ERROR_SEVERITIES.BUSINESS,
          store: true,
          error: {
            error: error,
            message: error.message || error,
            title: error.name || error,
          },
        };
        getErrorOrchestrator().handleError(options);
      }
    };
  }

  const columns: EuiBasicTableColumn<any>[] = [
    {
      field: 'id',
      name: i18n.translate('public.components.security.roles.mapping.components.table.id', {
        defaultMessage: 'ID',
      }),
      width: '75',
      sortable: true,
      truncateText: true,
    },
    {
      field: 'name',
      name: i18n.translate('public.components.security.roles.mapping.components.table.name', {
        defaultMessage: 'Name',
      }),
      sortable: true,
      truncateText: true,
    },
    {
      field: 'roles',
      name: i18n.translate('public.components.security.roles.mapping.components.table.roles', {
        defaultMessage: 'Roles',
      }),
      sortable: true,
      render: item => {
        const tmpRoles = item.map((role, idx) => {
          return (
            <EuiFlexItem key={`role_${idx}`} grow={false}>
              <EuiBadge color="secondary">{rolesEquivalences[role]}</EuiBadge>
            </EuiFlexItem>
          );
        });
        return (
          <EuiFlexGroup wrap responsive={false} gutterSize="xs">
            {tmpRoles}
          </EuiFlexGroup>
        );
      },
      truncateText: true,
    },
    {
      field: 'id',
      name: i18n.translate('public.components.security.roles.mapping.components.table.Status', {
        defaultMessage: 'Status',
      }),
      render(item, obj) {
        if (WzAPIUtils.isReservedID(item)) {
          if ((obj.id === 1 || obj.id === 2)) {
            return (
              <EuiFlexGroup>
                <EuiBadge color="primary">默认</EuiBadge>
                <EuiToolTip position="top" content="wui_ rules belong to wazuh-wui API user">
                  <EuiBadge color="accent" title="" style={{marginLeft: 10}}>wazuh-wui</EuiBadge>
                </EuiToolTip>
              </EuiFlexGroup>
            );
          } else
            return <EuiBadge color="primary">Reserved</EuiBadge>;
        }
      },
      width: '300',
      sortable: false,
    },
    {
      align: 'right',
      width: '5%',
      name: i18n.translate('public.components.security.roles.mapping.components.table.Actions', {
        defaultMessage: 'Actions',
      }),
      render: item => (
        <div onClick={ev => ev.stopPropagation()}>
          <WzButtonModalConfirm
            buttonType="icon"
            tooltip={{
              content:
                WzAPIUtils.isReservedID(item.id) ? "无法删除默认的角色映射" : '删除角色映射',
              position: 'left',
            }}
            isDisabled={WzAPIUtils.isReservedID(item.id)}
            modalTitle={`您确认要删除 ${item.name} 角色映射吗?`}
            onConfirm={onDeleteRoleMapping(item)}
            modalProps={{buttonColor: 'danger'}}
            iconType="trash"
            color="danger"
            aria-label="Delete role mapping"
            modalCancelText="Cancel"
            modalConfirmText="Confirm"
          />
        </div>
      ),
    },
  ];

  const sorting = {
    sort: {
      field: 'id',
      direction: SortDirection.ASC,
    },
  };

  const search = {
    box: {
      incremental: false,
      schema: true,
    },
  };

  return (
    <EuiInMemoryTable
      items={rules || []}
      columns={columns}
      search={search}
      rowProps={getRowProps}
      pagination={true}
      loading={loading}
      sorting={sorting}
    />
  );
};
