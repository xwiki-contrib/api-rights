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

import java.util.List;

import org.xwiki.contrib.rights.WritableSecurityRule;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.security.GroupSecurityReference;
import org.xwiki.security.UserSecurityReference;
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
    private List<DocumentReference> groups;

    private List<DocumentReference> users;

    private RightSet rights;

    private RuleState state;

    /**
     *
     */
    public WritableSecurityRuleImpl()
    {
    }

    /**
     * @param groups
     * @param users
     * @param rights
     * @param state
     */
    public WritableSecurityRuleImpl(List<DocumentReference> groups,
        List<DocumentReference> users, RightSet rights, RuleState state)
    {
        this.groups = groups;
        this.users = users;
        this.rights = rights;
        this.state = state;
    }

    /**
     * Sets the groups of this rule. Set null or empty list to reset to empty.
     *
     * @param groups references of groups to set
     */
    @Override public void setGroups(List<DocumentReference> groups)
    {
        this.groups = groups;
    }

    /**
     * Sets the groups of this rule. Set null or empty list to reset to empty.
     *
     * @param users references of users to set
     */
    @Override public void setUsers(List<DocumentReference> users)
    {
        this.users = users;
    }

    /**
     * Sets the rights of this rule, as a list of Right instances.
     *
     * @param rights the rights list
     */
    @Override public void setRights(List<Right> rights)
    {
        this.rights = new RightSet(rights);
    }

    /**
     * Sets the rights of this rule, as a RightSet.
     *
     * @param rights the right set instance containing the rights.
     */
    @Override public void setRights(RightSet rights)
    {
        this.rights = new RightSet(rights);
    }

    /**
     * Sets the rule state, allow or deny. If nothing is set, the default returned by the writable rule should be {@link
     * RuleState#ALLOW}.
     *
     * @param state the state of this rule.
     */
    @Override public void setState(RuleState state)
    {
        this.state = state;
    }

    @Override public List<DocumentReference> getUsers()
    {
        return users;
    }

    @Override public List<DocumentReference> getGroups()
    {
        return groups;
    }

    @Override public RightSet getRights()
    {
        return rights;
    }

    @Override public boolean isPersisted()
    {
        // TODO: to be implemented
        return false;
    }

    @Override public boolean match(Right right)
    {
        return rights.contains(right);
    }

    @Override public boolean match(GroupSecurityReference group)
    {
        return groups.contains(group.getOriginalDocumentReference());
    }

    @Override public boolean match(UserSecurityReference user)
    {
        return groups.contains(user.getOriginalReference());
    }

    @Override public RuleState getState()
    {
        return state;
    }
}
