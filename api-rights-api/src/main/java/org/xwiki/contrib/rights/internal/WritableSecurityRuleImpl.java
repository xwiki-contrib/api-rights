/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.contrib.rights.internal;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.xwiki.contrib.rights.WritableSecurityRule;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.security.GroupSecurityReference;
import org.xwiki.security.UserSecurityReference;
import org.xwiki.security.authorization.ReadableSecurityRule;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authorization.RightSet;
import org.xwiki.security.authorization.RuleState;

/**
 * Default implementation of a WritableSecurityRule.
 *
 * @version $Id$
 */
public class WritableSecurityRuleImpl implements WritableSecurityRule
{
    /**
     * By default, a {@link WritableSecurityRuleImpl} is marked as not persisted (even if it will be persisted in an
     * object at some point in time), so this flag will be set to false. However, if the current {@link
     * WritableSecurityRule} is created from a {@link ReadableSecurityRule} (maybe using {@link
     * WritableSecurityRuleImpl#WritableSecurityRuleImpl(ReadableSecurityRule)}), this field's value will be copied from
     * the given {@link ReadableSecurityRule}.
     */
    private final boolean isPersisted;

    private List<DocumentReference> groups;

    private List<DocumentReference> users;

    private RightSet rights;

    private RuleState state;

    /**
     * Creates a rule with no users, groups or rights. The rule is marked as not persisted.
     */
    public WritableSecurityRuleImpl()
    {
        this(new ArrayList<>(), new ArrayList<>(), new RightSet(), RuleState.ALLOW);
    }

    /**
     * Constructor to be used in order to create a WritableSecurityRuleImpl with given parameters. The rule will be
     * marked as not persisted.
     *
     * @param groups the groups to which the rule applies
     * @param users the users to which the rule applies
     * @param rights the rights concerned by this rule
     * @param state the state (allow or deny) for this rule. If null, {@link RuleState#ALLOW} should be used.
     */
    public WritableSecurityRuleImpl(List<DocumentReference> groups,
        List<DocumentReference> users, RightSet rights, RuleState state)
    {
        this.groups = groups;
        this.users = users;
        this.rights = rights;
        if (null != state) {
            this.state = state;
        } else {
            this.state = RuleState.ALLOW;
        }
        this.isPersisted = false;
    }

    /**
     * Create a WritableSecurityRuleImpl, which corresponds to a {@link ReadableSecurityRule}. Actually, this
     * constructor acts like an adapter between {@link ReadableSecurityRule} and {@link WritableSecurityRule}.
     * <p>
     * TODO: the difference between a WritableSecurityRule and a ReadableSecurityRule should be that the fields of the
     * ReadableSecurityRule can not be modified, since they're supposed to be immutable.
     *
     * @param rule the rule from which the fields will be copied
     */
    public WritableSecurityRuleImpl(ReadableSecurityRule rule)
    {
        this.groups = new ArrayList<>(rule.getGroups());
        this.users = new ArrayList<>(rule.getUsers());
        this.rights = rule.getRights();
        this.state = rule.getState();
        this.isPersisted = rule.isPersisted();
    }

    @Override
    public List<DocumentReference> getUsers()
    {
        return users;
    }

    /**
     * Sets the groups of this rule. Set null or empty list to reset to empty.
     *
     * @param users references of users to set
     */
    @Override
    public void setUsers(List<DocumentReference> users)
    {
        this.users = users;
    }

    @Override
    public List<DocumentReference> getGroups()
    {
        return groups;
    }

    /**
     * Sets the groups of this rule. Set null or empty list to reset to empty.
     *
     * @param groups references of groups to set
     */
    @Override
    public void setGroups(List<DocumentReference> groups)
    {
        this.groups = groups;
    }

    @Override
    public RightSet getRights()
    {
        return rights;
    }

    /**
     * Sets the rights of this rule, as a list of Right instances.
     *
     * @param rights the rights list
     */
    @Override
    public void setRights(List<Right> rights)
    {
        this.rights = new RightSet(rights);
    }

    /**
     * Sets the rights of this rule, as a RightSet.
     *
     * @param rights the right set instance containing the rights.
     */
    @Override
    public void setRights(RightSet rights)
    {
        this.rights = new RightSet(rights);
    }

    /**
     * @return true if the rule is already persisted, otherwise false. By using {@link
     *     WritableSecurityRuleImpl#WritableSecurityRuleImpl()} or {@link WritableSecurityRuleImpl#WritableSecurityRuleImpl(List,
     *     List, RightSet, RuleState)}, the rule is marked by default as not persisted. Otherwise, if the current rule
     *     comes from a {@link ReadableSecurityRule} (eventually using {@link WritableSecurityRuleImpl#WritableSecurityRuleImpl(ReadableSecurityRule)},
     *     the value of {@link WritableSecurityRuleImpl#isPersisted} will be copied from the object given as parameter.
     */
    @Override
    public boolean isPersisted()
    {
        return isPersisted;
    }

    @Override
    public boolean match(Right right)
    {
        return rights.contains(right);
    }

    @Override
    public boolean match(GroupSecurityReference group)
    {
        return groups.contains(group.getOriginalDocumentReference());
    }

    @Override
    public boolean match(UserSecurityReference user)
    {
        return groups.contains(user.getOriginalReference());
    }

    @Override
    public RuleState getState()
    {
        return state;
    }

    /**
     * Sets the rule state, allow or deny. If nothing is set, the default returned by the writable rule should be {@link
     * RuleState#ALLOW}.
     *
     * @param state the state of this rule.
     */
    @Override
    public void setState(RuleState state)
    {
        if (null != state) {
            this.state = state;
        } else {
            this.state = RuleState.ALLOW;
        }
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o) {
            return true;
        }

        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        WritableSecurityRuleImpl that = (WritableSecurityRuleImpl) o;

        return new EqualsBuilder()
            .append(groups, that.groups)
            .append(users, that.users)
            .append(rights, that.rights)
            .append(state, that.state)
            .isEquals();
    }

    @Override
    public int hashCode()
    {
        return new HashCodeBuilder(17, 37)
            .append(groups)
            .append(users)
            .append(rights)
            .append(state)
            .toHashCode();
    }
}
