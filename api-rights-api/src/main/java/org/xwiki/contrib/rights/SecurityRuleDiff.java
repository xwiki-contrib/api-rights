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

import java.util.Set;

import org.xwiki.security.authorization.ReadableSecurityRule;
import org.xwiki.stability.Unstable;

/**
 * Allow to see differences between set of {@link ReadableSecurityRule}.
 *
 * @version $Id$
 * @since 2.0
 */
@Unstable
public interface SecurityRuleDiff
{
    /**
     * Defines the type of properties contained in a {@link ReadableSecurityRule} and that might have been updated.
     *
     * @version $Id$
     */
    enum PropertyType
    {
        /**
         * See {@link ReadableSecurityRule#getState()}.
         */
        STATE,

        /**
         * See {@link ReadableSecurityRule#getGroups()}.
         */
        GROUPS,

        /**
         * See {@link ReadableSecurityRule#getUsers()}.
         */
        USERS,

        /**
         * See {@link ReadableSecurityRule#getRights()}.
         */
        RIGHTS
    }

    /**
     * Define the type of change found in a diff.
     *
     * @version $Id$
     */
    enum ChangeType
    {
        /**
         * When a new rule has been added.
         */
        RULE_ADDED,

        /**
         * When an existing rule has been updated.
         */
        RULE_UPDATED,

        /**
         * When a rule has been removed.
         */
        RULE_DELETED
    }

    /**
     * In case of rule deleted or updated, returns the rule before the changes.
     * In case of added rule, this should return null.
     * @return the previous version of a rule or null.
     */
    ReadableSecurityRule getPreviousRule();

    /**
     * In case of rule added or updated, returns the rule after the changes.
     * In case of deleted rule, this should return null.
     * @return the current version of a rule or null.
     */
    ReadableSecurityRule getCurrentRule();

    /**
     * @return the properties that have been changed in case of update, an empty set otherwise.
     */
    Set<PropertyType> getChangedProperties();

    /**
     * @return the type of change this diff is showing.
     */
    ChangeType getChangeType();
}
