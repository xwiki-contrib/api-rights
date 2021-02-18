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
package org.xwiki.contrib.rights;

import java.util.List;

import org.xwiki.model.reference.DocumentReference;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authorization.RightSet;
import org.xwiki.security.authorization.RuleState;
import org.xwki.security.authorization.ReadableSecurityRule;

/**
 * A writable security rule, on which the groups, users, rights and state can be set. Extends readable security rule, so
 * that operations on this type are read-write.
 *
 * @version $Id$
 */
public interface WritableSecurityRule extends ReadableSecurityRule
{
    /**
     * Sets the groups of this rule. Set null or empty list to reset to empty.
     *
     * @param groups references of groups to set
     */
    void setGroups(List<DocumentReference> groups);

    /**
     * Sets the groups of this rule. Set null or empty list to reset to empty.
     *
     * @param users references of users to set
     */
    void setUsers(List<DocumentReference> users);

    /**
     * Sets the rights of this rule, as a list of Right instances.
     *
     * @param rights the rights list
     */
    void setRights(List<Right> rights);

    /**
     * Sets the rights of this rule, as a RightSet.
     *
     * @param rights the right set instance containing the rights.
     */
    void setRights(RightSet rights);

    /**
     * Sets the rule state, allow or deny. If nothing is set, the default returned by the writable rule should be {@link
     * RuleState#ALLOW}.
     *
     * @param state the state of this rule.
     */
    void setState(RuleState state);
}
