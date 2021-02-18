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
// Use this package for the eventual case in which this interface will be patched in the platform; and then we can
// get rid of it from this module.
/*
 * Use this package for the eventual case in which this interface will be patched in the platform; and then we can
 * get rid of this interface.
 */
package org.xwki.security.authorization;

import java.util.List;

import org.xwiki.model.reference.DocumentReference;
import org.xwiki.security.authorization.RightSet;
import org.xwiki.security.authorization.SecurityRule;

/**
 * An improved version of SecurityRule, for which we can access groups, users, rights. Also, it provides support to
 * check if the rule is persisted.
 *
 * @version $Id: 74a6491a0587039a75ea967f80563d6a26554bfd $
 */
public interface ReadableSecurityRule extends SecurityRule
{
    /**
     * @return the users
     */
    List<DocumentReference> getUsers();

    /**
     * @return the groups
     */
    List<DocumentReference> getGroups();

    /**
     * @return the rights
     */
    RightSet getRights();

    /**
     * This method is used to check if the Right wrapped by current rule is an implicit one (that is actually stored) or
     * not.
     *
     * @return true if the rule is persisted (eg. in an object)
     */
    boolean isPersisted();
}

