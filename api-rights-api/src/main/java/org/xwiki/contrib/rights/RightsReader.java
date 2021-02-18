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
import org.xwiki.model.reference.EntityReference;
import org.xwiki.stability.Unstable;
import org.xwki.security.authorization.ReadableSecurityRule;

/**
 * @version $Id$
 * @since 1.0
 */
@Role
@Unstable
public interface RightsReader
{
    /**
     * Gets the rules that are stored for the passed entity (without inheritance).
     *
     * @param ref the entity reference to get the rules for
     * @param withImplied whether implied rules should also be returned or only persisted rules.
     * @return the list of security rules that apply to the passed entity
     */
    List<ReadableSecurityRule> getRules(EntityReference ref, Boolean withImplied);

    /**
     * Gets the persisted rules (without the implied rules) that are stored for the passed entity (without
     * inheritance).
     *
     * @param ref the entity reference to get the rules for
     * @return the list of security rules that apply to the passed entity
     */
    List<ReadableSecurityRule> getPersistedRules(EntityReference ref);

    /**
     * Gets the rules that apply to the passed entity reference, including the inherited and implied rules.
     *
     * @param ref the reference on which to check rules
     * @return the list of security rules that apply to the passed entity (including inherited and implied rules)
     */
    List<ReadableSecurityRule> getActualRules(EntityReference ref);
}
