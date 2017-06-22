using System;
using System.Collections.Generic;
using System.Linq;

namespace Cache
{
    using System.Configuration;
    using System.Runtime.Caching;
    using System.Web.Script.Serialization;
    using WebApi.OutputCache.Core.Cache;
    
    public class EncryptedWebApiCache : IApiOutputCache
    {
        private static string _passphrase;
        private static readonly MemoryCache Cache = MemoryCache.Default;

        private static string[] _excludeFromEncryption; 

        public EncryptedWebApiCache()
        {
            _passphrase = ConfigurationManager.AppSettings["EncryptionPassphrase"];
            _excludeFromEncryption = ConfigurationManager.AppSettings["ExcludeClassesFromEncryption"].Split(',');
        }

        public virtual void RemoveStartsWith(string key)
        {
            lock (Cache)
            {
                Cache.Remove(key);
            }
        }

        public virtual T Get<T>(string key) where T : class
        {
            if (NeedToEncrypt(typeof(T)))
            {
                var encryptedJson = Cache.Get(key) as string;

                var json = StringCipher.Decrypt(encryptedJson, _passphrase);

                var o = new JavaScriptSerializer().Deserialize<T>(json);

                return o;
            }

            var cacheObject = Cache.Get(key) as T;

            return cacheObject;
        }

        [Obsolete("Use Get<T> instead")]
        public virtual object Get(string key)
        {
            return Cache.Get(key);
        }

        public virtual void Remove(string key)
        {
            lock (Cache)
            {
                Cache.Remove(key);
            }
        }

        public virtual bool Contains(string key)
        {
            return Cache.Contains(key);
        }

        public virtual void Add(string key, object o, DateTimeOffset expiration, string dependsOnKey = null)
        {
            var cachePolicy = new CacheItemPolicy
            {
                AbsoluteExpiration = expiration
            };

            if (!string.IsNullOrWhiteSpace(dependsOnKey))
            {
                cachePolicy.ChangeMonitors.Add(
                    Cache.CreateCacheEntryChangeMonitor(new[] { dependsOnKey })
                );
            }
            lock (Cache)
            {
                if (NeedToEncrypt(o.GetType()))
                {
                    var json = new JavaScriptSerializer().Serialize(o);

                    var encryptedJson = StringCipher.Encrypt(json, _passphrase);

                    Cache.Add(key, encryptedJson, cachePolicy);
                    return;
                }

                Cache.Add(key, o, cachePolicy);
            }
        }

        public virtual IEnumerable<string> AllKeys
        {
            get
            {
                return Cache.Select(x => x.Key);
            }
        }

        public bool NeedToEncrypt(Type type)
        {
            var typeName = type.FullName;

            return !_excludeFromEncryption.Contains(typeName);
        }
    }
}