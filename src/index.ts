import {
	PluginOptions,
	AuthAccessCallback,
	AuthCallback,
	PackageAccess,
	IPluginAuth,
	RemoteUser,
	Logger,
	Callback,
} from '@verdaccio/types';
import { getInternalError } from '@verdaccio/commons-api';
import * as crypto from 'crypto';
import { CustomConfig } from '../types/index';
import { PrismaClient } from '@prisma/client'

/**
 * Custom Verdaccio Authenticate Plugin.
 */
export default class AuthMysqlPlugin implements IPluginAuth<CustomConfig> {
	public logger: Logger;
	private prisma: PrismaClient;
	private queries: ISqliteQueries;
	private password_secret: string;

	public constructor(config: CustomConfig, options: PluginOptions<CustomConfig>) {
		this.logger = options.logger;
		this.prisma = new PrismaClient({
			datasources: {
				db: {
					url: config.auth['auth-sqlite'].url
				}
			}
		})
		this.password_secret = config.auth['auth-sqlite'].password_secret;
		this.queries = new SqliteQueries();
		return this;
	}

	private hash(password: string): string {
		if (this.password_secret.length === 0) {
			return password;
		}

		const hashed = crypto.pbkdf2Sync(password, this.password_secret, 10000, 64, 'sha512');
		return hashed.toString('hex');
	}
	/**
	 * Authenticate an user.
	 * @param username user to log
	 * @param password provided password
	 * @param cb callback function
	 */
	public async authenticate(username: string, password: string, cb: Callback): Promise<void> {
		console.log("authenticate", username, password)
		try {
			const user = await this.prisma.users.findFirst({
				where: {
					username,
					password: this.hash(password)
				}
			})
			if (user) {
				const groups = await this.prisma.groupUsers.findMany({
					where: {
						user_id: user.id
					},
					select: {
						Groups: {
							select: {
								name: true,
							}
						}
					}
				})
				cb(null, groups.map(item => item.Groups?.name));
			} else {
				cb(getInternalError("error, try again"), false);
			}
		} catch (error) {
			cb(getInternalError("error, try again"), false);
		}
	}

	/**
	 * Triggered on each access request
	 * @param user
	 * @param pkg
	 * @param cb
	 */
	public allow_access(user: RemoteUser, pkg: PackageAccess, cb: AuthAccessCallback): void {
		console.log("allow_access", user, pkg)

		cb(null, true)
	}

	/**
	 * Triggered on each publish request
	 * @param user
	 * @param pkg
	 * @param cb
	 */
	public allow_publish(user: RemoteUser, pkg: PackageAccess, cb: AuthAccessCallback): void {
		/**
		 * This code is just an example for demostration purpose
		if (user.name === this.foo && pkg?.access?.includes[user.name]) {
		  this.logger.debug({name: user.name}, '@{name} has been granted to publish');
		  cb(null, true)
		} else {
		  this.logger.error({name: user.name}, '@{name} is not allowed to publish this package');
		   cb(getInternalError("error, try again"), false);
		}
		 */
		console.log("allow_publish", user, pkg)

		cb(null, true)
	}

	public allow_unpublish(user: RemoteUser, pkg: PackageAccess, cb: AuthAccessCallback): void {
		/**
		 * This code is just an example for demostration purpose
		if (user.name === this.foo && pkg?.access?.includes[user.name]) {
		  this.logger.debug({name: user.name}, '@{name} has been granted to unpublish');
		  cb(null, true)
		} else {
		  this.logger.error({name: user.name}, '@{name} is not allowed to publish this package');
		  cb(getInternalError("error, try again"), false);
		}
		 */
		console.log("allow_unpublish", user, pkg)

		cb(null, true)
	}

	public async adduser(user: string, password: string, cb: Callback) {

		try {
			if (!await this.prisma.users.count()) {
				console.log(await this.prisma.users.create({
					data: {
						username: user,
						password: this.hash(password),
					}
				}))
			}

			const userInfo = await this.prisma.users.findFirst({
				where: {
					username: user,
					password: this.hash(password),
				}
			})
			if (userInfo) {
				cb(null, true)
			} else {
				cb(getInternalError("error, try again"), false)
			}
		} catch (err) {
			cb(getInternalError("error, try again"), false)
		}
	}

	async changePassword(user: string, password: string, newPassword: string, cb: AuthCallback) {
		console.log("changePassword", user, password, newPassword)
		cb(null, false)
	}

}


interface ISqliteQueries {
	readonly add_user: boolean;
	readonly update_user: boolean;
	readonly auth_user: boolean;
}

class SqliteQueries implements ISqliteQueries {
	public get add_user(): boolean {
		return true;
	}

	public get update_user(): boolean {
		return true;
	}

	public get auth_user(): boolean {
		return true;
	}
}
