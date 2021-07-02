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

import org.xwiki.component.annotation.Role;
import org.xwiki.security.authorization.ReadableSecurityRule;

/**
 * The security abacus provides functions in order to perform various operations on security rules.
 *
 * @version $Id$
 * @since 1.1
 */
@Role
public interface SecurityRuleAbacus
{
    /**
     * Normalize given rules so that it is easier to use. The normalization will ensure that:
     * <ul>
     * <li>there is only one [subject, state] per rule</li>
     * <li>there is only one rule per [subject, state]</li>
     * </ul>
     *
     * @param rules A list of rules
     * @return The normalized list of rules
     */
    List<ReadableSecurityRule> normalizeRules(List<ReadableSecurityRule> rules);
}
