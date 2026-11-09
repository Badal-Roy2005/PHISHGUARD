/**
 * Minimal Chrome extension API surface used by this extension.
 *
 * There is deliberately no `@types/chrome` dependency here: the extension only
 * calls a small, auditable subset of MV3 APIs, and keeping the declarations in
 * the repository makes the exact capability set explicit.
 */

declare namespace chrome {
  namespace runtime {
    interface MessageSender {
      id?: string;
      url?: string;
      origin?: string;
      tab?: tabs.Tab;
    }

    interface Manifest {
      manifest_version: number;
      name: string;
      version: string;
      description?: string;
      host_permissions?: string[];
      permissions?: string[];
      [key: string]: unknown;
    }

    const id: string;

    function getManifest(): Manifest;
    function sendMessage(message: unknown): Promise<unknown>;

    interface MessageListener {
      (
        message: unknown,
        sender: MessageSender,
        sendResponse: (response?: unknown) => void,
      ): boolean | void;
    }

    const onMessage: {
      addListener(listener: MessageListener): void;
    };
  }

  namespace tabs {
    interface Tab {
      id?: number;
      url?: string;
      active?: boolean;
      windowId?: number;
    }

    interface QueryInfo {
      active?: boolean;
      lastFocusedWindow?: boolean;
      currentWindow?: boolean;
    }

    function query(queryInfo: QueryInfo): Promise<Tab[]>;
  }
}
